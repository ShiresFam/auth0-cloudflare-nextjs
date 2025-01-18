"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  Auth0Client: () => Auth0Client,
  createAuth0CloudflareContext: () => createAuth0CloudflareContext,
  getSession: () => getSession,
  handleAuth: () => handleAuth,
  handleCallback: () => handleCallback,
  handleLogin: () => handleLogin,
  handleLogout: () => handleLogout,
  withAuth: () => withAuth
});
module.exports = __toCommonJS(src_exports);

// src/auth0Client.ts
var jose = __toESM(require("jose"));
var Auth0Client = class {
  constructor(config) {
    let domain = config.domain;
    if (!/^https?:\/\//i.test(domain)) {
      domain = `https://${domain}`;
    }
    this.config = { ...config, domain };
    this.jwksClient = jose.createRemoteJWKSet(
      new URL(`${domain}/.well-known/jwks.json`)
    );
  }
  async getAuthorizationUrl(state) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      scope: "openid profile email",
      state
    });
    if (this.config.audience) {
      params.append("audience", this.config.audience);
    }
    return `${this.config.domain}/authorize?${params.toString()}`;
  }
  async exchangeCodeForTokens(code) {
    const response = await fetch(`${this.config.domain}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        redirect_uri: this.config.callbackUrl
      })
    });
    if (!response.ok) {
      throw new Error("Failed to exchange code for tokens");
    }
    return response.json();
  }
  async verifyToken(token) {
    return jose.jwtVerify(token, this.jwksClient, {
      issuer: `${this.config.domain}/`,
      audience: this.config.clientId
    });
  }
  async refreshToken(refreshToken) {
    const response = await fetch(`${this.config.domain}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: refreshToken
      })
    });
    if (!response.ok) {
      throw new Error("Failed to refresh token");
    }
    return response.json();
  }
};

// src/withAuth.ts
var import_server = require("next/server");
function withAuth(handler) {
  return async (req, context) => {
    const { env } = context;
    console.log("env", env);
    const auth0Client = new Auth0Client({
      domain: env.AUTH0_DOMAIN,
      clientId: env.AUTH0_CLIENT_ID,
      clientSecret: env.AUTH0_CLIENT_SECRET,
      callbackUrl: env.AUTH0_CALLBACK_URL,
      audience: env.AUTH0_AUDIENCE
    });
    const accessToken = req.cookies.get("access_token")?.value;
    if (!accessToken) {
      return import_server.NextResponse.redirect(new URL("/api/auth/login", req.url));
    }
    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq = new import_server.NextRequest(req, {
        headers: req.headers
      });
      authenticatedReq.auth = {
        token: accessToken,
        payload: verifyResult.payload
      };
      return handler(authenticatedReq, context);
    } catch (error) {
      const refreshToken = req.cookies.get("refresh_token")?.value;
      if (refreshToken) {
        try {
          const newTokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(
            newTokens.access_token
          );
          const authenticatedReq = new import_server.NextRequest(req, {
            headers: req.headers
          });
          authenticatedReq.auth = {
            token: newTokens.access_token,
            payload: verifyResult.payload
          };
          const response = await handler(authenticatedReq, context);
          const nextResponse = import_server.NextResponse.json(
            response instanceof Response ? await response.json() : response,
            {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers
            }
          );
          nextResponse.cookies.set("access_token", newTokens.access_token, {
            httpOnly: true,
            secure: true
          });
          if (newTokens.refresh_token) {
            nextResponse.cookies.set("refresh_token", newTokens.refresh_token, {
              httpOnly: true,
              secure: true
            });
          }
          return nextResponse;
        } catch (refreshError) {
          return import_server.NextResponse.redirect(new URL("/api/auth/login", req.url));
        }
      } else {
        return import_server.NextResponse.redirect(new URL("/api/auth/login", req.url));
      }
    }
  };
}

// src/authUtils.ts
var import_server2 = require("next/server");

// src/contextUtils.ts
function createAuth0CloudflareContext(baseContext) {
  const requiredEnvVars = [
    "AUTH0_DOMAIN",
    "AUTH0_CLIENT_ID",
    "AUTH0_CLIENT_SECRET",
    "AUTH0_CALLBACK_URL"
  ];
  const missingEnvVars = requiredEnvVars.filter(
    (varName) => !(varName in baseContext.env)
  );
  if (missingEnvVars.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingEnvVars.join(", ")}`
    );
  }
  const auth0Env = {
    AUTH0_DOMAIN: baseContext.env.AUTH0_DOMAIN,
    AUTH0_CLIENT_ID: baseContext.env.AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET: baseContext.env.AUTH0_CLIENT_SECRET,
    AUTH0_CALLBACK_URL: baseContext.env.AUTH0_CALLBACK_URL,
    AUTH0_AUDIENCE: baseContext.env.AUTH0_AUDIENCE
  };
  return {
    ...baseContext,
    env: {
      ...baseContext.env,
      ...auth0Env
    }
  };
}

// src/authUtils.ts
async function handleLogin(req, context) {
  const auth0Context = createAuth0CloudflareContext(context);
  const { env } = auth0Context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE
  });
  console.log("req.url from login", req.url);
  const state = crypto.randomUUID();
  const authorizationUrl = await auth0Client.getAuthorizationUrl(state);
  console.log("authorization_url", authorizationUrl);
  const response = import_server2.NextResponse.redirect(authorizationUrl);
  response.cookies.set("auth_state", state, { httpOnly: true, secure: true });
  return response;
}
async function handleCallback(req, context) {
  const auth0Context = createAuth0CloudflareContext(context);
  const { env } = auth0Context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE
  });
  const origin = new URL(env.AUTH0_CALLBACK_URL).origin;
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const storedState = req.cookies.get("auth_state")?.value;
  if (!code || !state || !storedState || state !== storedState) {
    return import_server2.NextResponse.redirect(new URL("/api/login", req.url));
  }
  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);
    console.log("req.url for callback", req.url);
    const response = import_server2.NextResponse.redirect(new URL("/", req.url));
    console.log("response.url for callback", new URL("/", req.url).toString());
    response.cookies.set("access_token", tokens.access_token, {
      httpOnly: true,
      secure: true
    });
    if (tokens.refresh_token) {
      response.cookies.set("refresh_token", tokens.refresh_token, {
        httpOnly: true,
        secure: true
      });
    }
    response.cookies.delete("auth_state");
    return response;
  } catch (error) {
    console.error("Error during callback:", error);
    return import_server2.NextResponse.redirect(new URL("/api/login", req.url));
  }
}
async function handleLogout(req) {
  const response = import_server2.NextResponse.redirect(new URL("/", req.url));
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  return response;
}

// src/handleAuth.ts
var import_server4 = require("next/server");
var import_cloudflare = require("@opennextjs/cloudflare");

// src/utils/request.ts
var import_server3 = require("next/server");
function createProperRequest(originalRequest) {
  const referer = originalRequest.headers.get("referer");
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const originalUrl = new URL(originalRequest.url);
      const properUrl = new URL(
        originalUrl.pathname + originalUrl.search,
        refererUrl.origin
      );
      console.log("Created proper URL from referer:", properUrl.toString());
      return new import_server3.NextRequest(properUrl, {
        method: originalRequest.method,
        headers: originalRequest.headers,
        body: originalRequest.body,
        credentials: originalRequest.credentials
      });
    } catch (e) {
      console.warn("Failed to parse referer URL:", e);
    }
  }
  const forwardedHost = originalRequest.headers.get("x-forwarded-host");
  const forwardedProto = originalRequest.headers.get("x-forwarded-proto");
  if (forwardedHost && forwardedProto) {
    const originalUrl = new URL(originalRequest.url);
    const properUrl = new URL(
      originalUrl.pathname + originalUrl.search,
      `${forwardedProto}://${forwardedHost}`
    );
    console.log(
      "Created proper URL from forwarded headers:",
      properUrl.toString()
    );
    return new import_server3.NextRequest(properUrl, {
      method: originalRequest.method,
      headers: originalRequest.headers,
      body: originalRequest.body,
      credentials: originalRequest.credentials
    });
  }
  console.warn("No proper headers found to create URL, using original request");
  return originalRequest;
}

// src/handleAuth.ts
function handleAuth() {
  return async (req) => {
    try {
      const context = await (0, import_cloudflare.getCloudflareContext)();
      const properRequest = createProperRequest(req);
      console.log("Auth handler processing:", {
        originalUrl: req.url,
        properUrl: properRequest.url,
        pathname: new URL(properRequest.url).pathname
      });
      return await handleAuthRequest(properRequest, context);
    } catch (error) {
      console.error("Auth handler error:", error);
      return new import_server4.NextResponse("Internal Server Error", { status: 500 });
    }
  };
}
async function handleAuthRequest(req, context) {
  const url = new URL(req.url);
  const { pathname } = url;
  switch (pathname) {
    case "/api/auth/login":
      return handleLogin(req, context);
    case "/api/auth/callback":
      return handleCallback(req, context);
    case "/api/auth/logout":
      return handleLogout(req);
    default:
      return new import_server4.NextResponse("Not Found", { status: 404 });
  }
}

// src/getSession.ts
async function getSession(req, context) {
  const auth0Context = createAuth0CloudflareContext(context);
  const { env } = auth0Context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE
  });
  const accessToken = req.cookies.get("access_token")?.value;
  if (!accessToken) {
    return null;
  }
  try {
    const verifyResult = await auth0Client.verifyToken(accessToken);
    return {
      user: verifyResult.payload,
      accessToken
    };
  } catch (error) {
    console.error("Error verifying token:", error);
    return null;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Auth0Client,
  createAuth0CloudflareContext,
  getSession,
  handleAuth,
  handleCallback,
  handleLogin,
  handleLogout,
  withAuth
});
