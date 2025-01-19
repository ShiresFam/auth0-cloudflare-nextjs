"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  Auth0Client: () => Auth0Client,
  createAuth0CloudflareContext: () => createAuth0CloudflareContext,
  getSession: () => getSession,
  handleAuth: () => handleAuth,
  handleCallback: () => handleCallback,
  handleGetUser: () => handleGetUser,
  handleLogin: () => handleLogin,
  handleLogout: () => handleLogout,
  setAuthUtilOptions: () => setAuthUtilOptions,
  withAuth: () => withAuth
});
module.exports = __toCommonJS(src_exports);

// src/auth0Client.ts
var import_jwt_decode = require("jwt-decode");
var Auth0Client = class {
  constructor(config) {
    this.config = {
      ...config,
      domain: this.ensureHttps(config.domain),
      callbackUrl: this.ensureCorrectProtocol(config.callbackUrl)
    };
  }
  ensureHttps(url) {
    if (url.startsWith("http://") || url.startsWith("https://")) {
      return url;
    }
    return `https://${url}`;
  }
  ensureCorrectProtocol(url) {
    const urlObject = new URL(url);
    if (urlObject.hostname === "localhost" || urlObject.hostname.includes("127.0.0.1")) {
      urlObject.protocol = "http:";
    } else {
      urlObject.protocol = "https:";
    }
    return urlObject.toString();
  }
  normalizeUrl(url) {
    return url.endsWith("/") ? url.slice(0, -1) : url;
  }
  async getAuthorizationUrl(state) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      scope: "openid profile email name",
      state
    });
    if (this.config.audience) {
      params.append("audience", this.config.audience);
    }
    const authorizationUrl = `${this.config.domain}/authorize?${params.toString()}`;
    console.log("Generated Authorization URL:", authorizationUrl);
    return authorizationUrl;
  }
  async exchangeCodeForTokens(code) {
    const tokenUrl = `${this.config.domain}/oauth/token`;
    const body = JSON.stringify({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      redirect_uri: this.config.callbackUrl
    });
    console.log("Exchanging code for tokens. Token URL:", tokenUrl);
    console.log("Request body:", body);
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.error("Failed to exchange code for tokens. Status:", response.status, "Error:", errorText);
      throw new Error(`Failed to exchange code for tokens: ${errorText}`);
    }
    const tokens = await response.json();
    if (!this.isValidTokenResponse(tokens)) {
      console.error("Invalid token response:", tokens);
      throw new Error("Invalid token response");
    }
    console.log("Received tokens:", JSON.stringify(tokens, null, 2));
    if (tokens.id_token) {
      const decodedIdToken = (0, import_jwt_decode.jwtDecode)(tokens.id_token);
      console.log("Decoded ID Token:", JSON.stringify(decodedIdToken, null, 2));
    } else {
      console.warn("No ID token received in the token response");
    }
    return tokens;
  }
  isValidTokenResponse(tokens) {
    return typeof tokens === "object" && tokens !== null && "access_token" in tokens && typeof tokens.access_token === "string" && "id_token" in tokens && typeof tokens.id_token === "string" && "expires_in" in tokens && typeof tokens.expires_in === "number" && "token_type" in tokens && typeof tokens.token_type === "string" && (!("refresh_token" in tokens) || typeof tokens.refresh_token === "string");
  }
  async verifyToken(token) {
    try {
      const decodedToken = (0, import_jwt_decode.jwtDecode)(token);
      console.log("Decoded token:", decodedToken);
      const now = Math.floor(Date.now() / 1e3);
      if (typeof decodedToken.exp === "number" && decodedToken.exp < now) {
        throw new Error("Token has expired");
      }
      if (typeof decodedToken.nbf === "number" && decodedToken.nbf > now) {
        throw new Error("Token is not yet valid");
      }
      if (this.normalizeUrl(decodedToken.iss) !== this.normalizeUrl(this.config.domain)) {
        console.error("Token issuer mismatch:", {
          tokenIssuer: decodedToken.iss,
          expectedIssuer: this.config.domain
        });
        throw new Error("Token issuer is invalid");
      }
      const tokenAudience = decodedToken.aud;
      const tokenAzp = decodedToken.azp;
      if (Array.isArray(tokenAudience)) {
        if (!tokenAudience.includes(this.config.clientId)) {
          if (tokenAzp !== this.config.clientId) {
            console.error("Token audience and azp mismatch:", {
              tokenAudience,
              tokenAzp,
              expectedAudience: this.config.clientId
            });
            throw new Error("Token audience and authorized party are invalid");
          }
        }
      } else if (tokenAudience !== this.config.clientId) {
        if (tokenAzp !== this.config.clientId) {
          console.error("Token audience and azp mismatch:", {
            tokenAudience,
            tokenAzp,
            expectedAudience: this.config.clientId
          });
          throw new Error("Token audience and authorized party are invalid");
        }
      }
      console.log("Token verification successful");
      return { payload: decodedToken };
    } catch (error) {
      console.error("Error verifying token:", error);
      throw new Error("Invalid token");
    }
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
      const errorText = await response.text();
      console.error("Failed to refresh token. Status:", response.status, "Error:", errorText);
      throw new Error(`Failed to refresh token: ${errorText}`);
    }
    const tokens = await response.json();
    if (!this.isValidTokenResponse(tokens)) {
      console.error("Invalid token response:", tokens);
      throw new Error("Invalid token response");
    }
    return tokens;
  }
  async getUserInfo(accessToken) {
    const response = await fetch(`${this.config.domain}/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });
    if (!response.ok) {
      throw new Error("Failed to fetch user info");
    }
    const userInfo = await response.json();
    console.log("User Info:", JSON.stringify(userInfo, null, 2));
    return userInfo;
  }
  getLogoutUrl(returnTo) {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      returnTo
    });
    return `${this.config.domain}/v2/logout?${params.toString()}`;
  }
};

// src/withAuth.ts
var import_server = require("next/server");
var import_cloudflare2 = require("@opennextjs/cloudflare");

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

// src/urlUtils.ts
var import_cloudflare = require("@opennextjs/cloudflare");
async function constructBaseUrl(req) {
  const cloudflareContext = await (0, import_cloudflare.getCloudflareContext)();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  if (env.AUTH0_BASE_URL) {
    return env.AUTH0_BASE_URL;
  }
  let protocol = req.headers.get("x-forwarded-proto") || "http";
  const host = req.headers.get("x-forwarded-host") || req.headers.get("host") || "localhost:8000";
  if (!host.includes("localhost") && !host.includes("127.0.0.1")) {
    protocol = "https";
  }
  const baseUrl = `${protocol}://${host}`;
  console.log("Constructed Base URL:", baseUrl);
  return baseUrl;
}
async function constructFullUrl(req, path) {
  const baseUrl = await constructBaseUrl(req);
  const fullUrl = new URL(path, baseUrl).toString();
  console.log("Constructed Full URL:", fullUrl);
  return fullUrl;
}

// src/withAuth.ts
function withAuth(handler) {
  return async (req) => {
    const cloudflareContext = await (0, import_cloudflare2.getCloudflareContext)();
    const context = createAuth0CloudflareContext(cloudflareContext);
    const { env } = context;
    const auth0Client = new Auth0Client({
      domain: env.AUTH0_DOMAIN,
      clientId: env.AUTH0_CLIENT_ID,
      clientSecret: env.AUTH0_CLIENT_SECRET,
      callbackUrl: await constructFullUrl(req, "/api/auth/callback"),
      audience: env.AUTH0_AUDIENCE
    });
    const accessToken = req.cookies.get("access_token")?.value;
    if (!accessToken) {
      return import_server.NextResponse.redirect(await constructFullUrl(req, "/api/auth/login"));
    }
    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq = new import_server.NextRequest(req, {
        headers: new Headers(req.headers)
      });
      authenticatedReq.auth = {
        token: accessToken,
        payload: verifyResult.payload
      };
      authenticatedReq.headers.set("Authorization", `Bearer ${accessToken}`);
      return handler(authenticatedReq);
    } catch (error) {
      console.error("Error verifying token:", error);
      const refreshToken = req.cookies.get("refresh_token")?.value;
      if (refreshToken) {
        try {
          const tokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(tokens.access_token);
          const authenticatedReq = new import_server.NextRequest(req, {
            headers: new Headers(req.headers)
          });
          authenticatedReq.auth = {
            token: tokens.access_token,
            payload: verifyResult.payload
          };
          authenticatedReq.headers.set("Authorization", `Bearer ${tokens.access_token}`);
          const response = await handler(authenticatedReq);
          const secureCookie = env.DISABLE_SECURE_COOKIES !== "true";
          response.cookies.set("access_token", tokens.access_token, {
            httpOnly: true,
            secure: secureCookie
          });
          if (tokens.refresh_token) {
            response.cookies.set("refresh_token", tokens.refresh_token, {
              httpOnly: true,
              secure: secureCookie
            });
          }
          return response;
        } catch (refreshError) {
          console.error("Error refreshing token:", refreshError);
        }
      }
      return import_server.NextResponse.redirect(await constructFullUrl(req, "/api/auth/login"));
    }
  };
}

// src/authUtils.ts
var import_server2 = require("next/server");
var import_cloudflare3 = require("@opennextjs/cloudflare");
var customOptions = {};
function setAuthUtilOptions(options) {
  customOptions = options;
}
async function handleLogin(req) {
  const cloudflareContext = await (0, import_cloudflare3.getCloudflareContext)();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const callbackUrl = await constructFullUrl(req, "/api/auth/callback");
  console.log("Auth0 Configuration:", {
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    callbackUrl,
    audience: env.AUTH0_AUDIENCE
  });
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl,
    audience: env.AUTH0_AUDIENCE
  });
  if (customOptions.onLogin) {
    return customOptions.onLogin(req, context, auth0Client);
  }
  try {
    const state = crypto.randomUUID();
    const authorizationUrl = await auth0Client.getAuthorizationUrl(state);
    console.log("Login - Authorization URL:", authorizationUrl);
    const response = import_server2.NextResponse.redirect(authorizationUrl);
    const secureCookie = env.DISABLE_SECURE_COOKIES !== "true";
    response.cookies.set("auth_state", state, { httpOnly: true, secure: secureCookie });
    return response;
  } catch (error) {
    console.error("Error in handleLogin:", error);
    return import_server2.NextResponse.redirect(await constructFullUrl(req, "/auth/error"));
  }
}
async function handleCallback(req) {
  const cloudflareContext = await (0, import_cloudflare3.getCloudflareContext)();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const callbackUrl = await constructFullUrl(req, "/api/auth/callback");
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl,
    audience: env.AUTH0_AUDIENCE
  });
  if (customOptions.onCallback) {
    return customOptions.onCallback(req, context, auth0Client);
  }
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");
  console.log("Callback - Received params:", { code, state, error, errorDescription });
  const storedState = req.cookies.get("auth_state")?.value;
  if (error) {
    console.error("Auth0 error:", error, errorDescription);
    return import_server2.NextResponse.redirect(await constructFullUrl(req, "/auth/error"));
  }
  if (!code || !state || !storedState || state !== storedState) {
    console.error("Invalid callback parameters");
    return import_server2.NextResponse.redirect(await constructFullUrl(req, "/api/auth/login"));
  }
  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);
    const userInfo = await auth0Client.getUserInfo(tokens.access_token);
    const response = import_server2.NextResponse.redirect(await constructFullUrl(req, "/"));
    const secureCookie = env.DISABLE_SECURE_COOKIES !== "true";
    response.cookies.set("access_token", tokens.access_token, {
      httpOnly: true,
      secure: secureCookie
    });
    if (tokens.refresh_token) {
      response.cookies.set("refresh_token", tokens.refresh_token, {
        httpOnly: true,
        secure: secureCookie
      });
    }
    response.cookies.delete("auth_state");
    response.cookies.set("user_info", JSON.stringify(userInfo), {
      httpOnly: true,
      secure: secureCookie,
      maxAge: 7 * 24 * 60 * 60
      // 7 days
    });
    return response;
  } catch (error2) {
    console.error("Error during callback:", error2);
    return import_server2.NextResponse.redirect(await constructFullUrl(req, "/auth/error"));
  }
}
async function handleLogout(req) {
  const cloudflareContext = await (0, import_cloudflare3.getCloudflareContext)();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: await constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE
  });
  if (customOptions.onLogout) {
    return customOptions.onLogout(req, context, auth0Client);
  }
  const returnTo = await constructFullUrl(req, "/");
  const logoutUrl = auth0Client.getLogoutUrl(returnTo);
  const response = import_server2.NextResponse.redirect(logoutUrl);
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  response.cookies.delete("user_info");
  return response;
}
async function handleGetUser(req) {
  const cloudflareContext = await (0, import_cloudflare3.getCloudflareContext)();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: await constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE
  });
  if (customOptions.onGetUser) {
    return customOptions.onGetUser(req, context, auth0Client);
  }
  const accessToken = req.cookies.get("access_token")?.value;
  const userInfoCookie = req.cookies.get("user_info")?.value;
  if (!accessToken || !userInfoCookie) {
    return import_server2.NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    await auth0Client.verifyToken(accessToken);
    const userInfo = JSON.parse(userInfoCookie);
    return import_server2.NextResponse.json(userInfo);
  } catch (error) {
    console.error("Error verifying token:", error);
    return import_server2.NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}

// src/handleAuth.ts
var import_server3 = require("next/server");

// src/getSession.ts
var import_cloudflare4 = require("@opennextjs/cloudflare");
async function getSession(req) {
  const cloudflareContext = await (0, import_cloudflare4.getCloudflareContext)();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: await constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE
  });
  const accessToken = req.cookies.get("access_token")?.value;
  const userInfoCookie = req.cookies.get("user_info")?.value;
  if (!accessToken || !userInfoCookie) {
    return null;
  }
  try {
    await auth0Client.verifyToken(accessToken);
    const userInfo = JSON.parse(userInfoCookie);
    return {
      user: userInfo,
      accessToken
    };
  } catch (error) {
    console.error("Error verifying token:", error);
    return null;
  }
}

// src/handleAuth.ts
function handleAuth() {
  return async (req) => {
    const { pathname } = new URL(req.url);
    console.log("pathname", pathname);
    console.log("req.url", req.nextUrl);
    console.log("headers", req.headers);
    switch (pathname) {
      case "/api/auth/login":
        return handleLogin(req);
      case "/api/auth/callback":
        return handleCallback(req);
      case "/api/auth/logout":
        return handleLogout(req);
      case "/api/auth/me":
        const session = await getSession(req);
        if (session?.user) {
          return import_server3.NextResponse.json(session.user);
        }
        return new import_server3.NextResponse("Unauthorized", { status: 401 });
      default:
        return new import_server3.NextResponse("Not Found", { status: 404 });
    }
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Auth0Client,
  createAuth0CloudflareContext,
  getSession,
  handleAuth,
  handleCallback,
  handleGetUser,
  handleLogin,
  handleLogout,
  setAuthUtilOptions,
  withAuth
});
