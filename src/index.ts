import express from "express";
import cors from "cors";
import { randomUUID } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { createServer } from "@mauricio.wolff/mcp-obsidian";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import {
  mcpAuthMetadataRouter,
  getOAuthProtectedResourceMetadataUrl,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { createRemoteJWKSet, jwtVerify } from "jose";
import rateLimit from "express-rate-limit";

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

const MAX_SESSIONS = 100;

function fatal(msg: string): never {
  console.error(`FATAL: ${msg}`);
  process.exit(1);
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) fatal(`${name} is required`);
  return value;
}

const vaultPath = requireEnv("VAULT_PATH");
const port = parseInt(process.env["PORT"] ?? "3000", 10);
const oauthAudience = requireEnv("OAUTH_AUDIENCE");

// Validate VAULT_PATH exists and is a directory
if (!existsSync(vaultPath)) fatal(`VAULT_PATH does not exist: ${vaultPath}`);
if (!statSync(vaultPath).isDirectory())
  fatal(`VAULT_PATH is not a directory: ${vaultPath}`);
if (vaultPath === "/") fatal("VAULT_PATH must not be the filesystem root");

// Validate URLs are parseable
let issuerUrl: URL;
let serverUrl: URL;
try {
  issuerUrl = new URL(requireEnv("OAUTH_ISSUER_URL"));
} catch {
  fatal(`OAUTH_ISSUER_URL is not a valid URL: ${process.env["OAUTH_ISSUER_URL"]}`);
}
try {
  serverUrl = new URL(requireEnv("SERVER_URL"));
} catch {
  fatal(`SERVER_URL is not a valid URL: ${process.env["SERVER_URL"]}`);
}

// Validate OAUTH_ISSUER_URL uses HTTPS (except localhost)
if (
  issuerUrl.protocol !== "https:" &&
  issuerUrl.hostname !== "localhost" &&
  issuerUrl.hostname !== "127.0.0.1"
) {
  fatal("OAUTH_ISSUER_URL must use HTTPS (except for localhost)");
}

const allowedOrigins = requireEnv("ALLOWED_ORIGINS").split(",").map((o) => o.trim());

// ---------------------------------------------------------------------------
// OAuth metadata fetching
// ---------------------------------------------------------------------------

async function fetchOAuthMetadata(issuer: URL): Promise<OAuthMetadata> {
  const endpoints = [
    new URL(".well-known/openid-configuration", issuer),
    new URL(".well-known/oauth-authorization-server", issuer),
  ];

  for (const endpoint of endpoints) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      const res = await fetch(endpoint.toString(), {
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!res.ok) continue;

      const metadata = (await res.json()) as OAuthMetadata;

      // Validate minimum required fields
      if (
        !metadata.issuer ||
        !metadata.authorization_endpoint ||
        !metadata.token_endpoint
      ) {
        continue;
      }

      return metadata;
    } catch {
      continue;
    }
  }

  fatal(
    `Could not fetch OAuth metadata from ${issuer}. Tried .well-known/openid-configuration and .well-known/oauth-authorization-server`,
  );
}

// ---------------------------------------------------------------------------
// JWT token verifier
// ---------------------------------------------------------------------------

function createTokenVerifier(
  issuer: string,
  audience: string,
  jwksUri: URL,
): OAuthTokenVerifier {
  const JWKS = createRemoteJWKSet(jwksUri);

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      try {
        const { payload } = await jwtVerify(token, JWKS, {
          issuer,
          audience,
          algorithms: ["RS256", "PS256"],
        });

        const clientId = (payload.azp as string | undefined) ??
          (payload.sub as string | undefined);

        if (!clientId) {
          console.error("Token verification failed: missing sub and azp claims");
          throw new InvalidTokenError("Token verification failed");
        }

        const scopes: string[] =
          typeof payload.scope === "string"
            ? payload.scope.split(" ").filter(Boolean)
            : [];

        return {
          token,
          clientId,
          scopes,
          expiresAt: payload.exp,
        };
      } catch (err) {
        if (err instanceof InvalidTokenError) throw err;
        console.error("Token verification failed:", err);
        throw new InvalidTokenError("Token verification failed");
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // 1. Fetch OAuth metadata
  console.log(`Fetching OAuth metadata from ${issuerUrl}...`);
  const oauthMetadata = await fetchOAuthMetadata(issuerUrl);
  console.log(`OAuth metadata fetched. Issuer: ${oauthMetadata.issuer}`);

  // 2. Extract jwks_uri
  const jwksUriStr =
    (oauthMetadata as Record<string, unknown>)["jwks_uri"] as
      | string
      | undefined;
  if (!jwksUriStr) {
    fatal("OAuth metadata does not contain jwks_uri");
  }
  const jwksUri = new URL(jwksUriStr);

  // 3. Create token verifier
  const verifier = createTokenVerifier(
    oauthMetadata.issuer,
    oauthAudience,
    jwksUri,
  );

  // 4. Build resource metadata URL and auth middleware
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(serverUrl);
  const authMiddleware = requireBearerAuth({
    verifier,
    requiredScopes: [],
    resourceMetadataUrl,
  });

  // 5. Express app setup
  const app = express();

  app.use(express.json());

  app.use(
    cors({
      origin: allowedOrigins,
      exposedHeaders: ["Mcp-Session-Id"],
    }),
  );

  // 6. Rate limiting
  const globalLimiter = rateLimit({
    windowMs: 60_000,
    limit: 100,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Too many requests, please try again later" },
  });
  app.use(globalLimiter);

  const initLimiter = rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Too many session initializations, please try again later" },
  });

  // 7. Mount auth metadata router (unauthenticated)
  app.use(
    mcpAuthMetadataRouter({
      oauthMetadata,
      resourceServerUrl: serverUrl,
    }),
  );

  // 8. Session management
  const transports: Record<string, StreamableHTTPServerTransport> = {};
  const sessionOwners: Record<string, string> = {};

  // Extract allowed hosts for DNS rebinding protection
  const allowedHosts = [serverUrl.host];

  // 9. POST /mcp (authenticated)
  app.post("/mcp", authMiddleware, async (req, res) => {
    const auth = req.auth as AuthInfo;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (sessionId && transports[sessionId]) {
      // Verify session ownership
      if (sessionOwners[sessionId] !== auth.clientId) {
        res.status(403).json({ error: "Session belongs to a different client" });
        return;
      }
      // Reuse existing transport
      await transports[sessionId]!.handleRequest(req, res, req.body);
      return;
    }

    if (!sessionId && isInitializeRequest(req.body)) {
      // Apply stricter rate limit to session initialization only.
      // express-rate-limit either calls next() (allowed) or sends a 429 response (blocked).
      const allowed = await new Promise<boolean>((resolve) => {
        res.on("finish", () => resolve(false));
        initLimiter(req, res, () => {
          res.removeAllListeners("finish");
          resolve(true);
        });
      });
      if (!allowed) return;
      // Check session cap
      if (Object.keys(transports).length >= MAX_SESSIONS) {
        res
          .status(503)
          .json({ error: "Maximum concurrent sessions reached" });
        return;
      }

      // Create new transport + server
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid) => {
          transports[sid] = transport;
          sessionOwners[sid] = auth.clientId;
          console.log(
            `Session ${sid} created for client ${auth.clientId}`,
          );
        },
        onsessionclosed: (sid) => {
          delete transports[sid];
          delete sessionOwners[sid];
          console.log(`Session ${sid} closed`);
        },
        enableDnsRebindingProtection: true,
        allowedHosts,
        allowedOrigins,
      });

      const server = createServer(vaultPath);
      await server.connect(transport);

      await transport.handleRequest(req, res, req.body);
      return;
    }

    // Neither existing session nor initialize request
    res.status(400).json({
      error:
        "Bad request: missing Mcp-Session-Id header or not an initialize request",
    });
  });

  // 10. GET /mcp (authenticated) - SSE stream
  app.get("/mcp", authMiddleware, async (req, res) => {
    const auth = req.auth as AuthInfo;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (!sessionId || !transports[sessionId]) {
      res.status(400).json({ error: "Invalid or missing session ID" });
      return;
    }

    if (sessionOwners[sessionId] !== auth.clientId) {
      res.status(403).json({ error: "Session belongs to a different client" });
      return;
    }

    await transports[sessionId]!.handleRequest(req, res);
  });

  // 11. DELETE /mcp (authenticated) - session termination
  app.delete("/mcp", authMiddleware, async (req, res) => {
    const auth = req.auth as AuthInfo;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (!sessionId || !transports[sessionId]) {
      res.status(400).json({ error: "Invalid or missing session ID" });
      return;
    }

    if (sessionOwners[sessionId] !== auth.clientId) {
      res.status(403).json({ error: "Session belongs to a different client" });
      return;
    }

    await transports[sessionId]!.handleRequest(req, res);
  });

  // 12. Start listening
  app.listen(port, () => {
    console.log(`MCP server listening on port ${port}`);
    console.log(`Server URL: ${serverUrl}`);
    console.log(`Vault path: ${vaultPath}`);
    console.log(
      `Protected resource metadata: ${resourceMetadataUrl}`,
    );
  });

  // 13. Graceful shutdown
  async function shutdown(signal: string): Promise<void> {
    console.log(`\n${signal} received, shutting down...`);
    for (const [sid, transport] of Object.entries(transports)) {
      console.log(`Closing session ${sid}`);
      await transport.close();
    }
    process.exit(0);
  }
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
