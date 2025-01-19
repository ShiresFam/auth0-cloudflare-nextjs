// src/auth0Client.ts
var Auth0Client = class {
  constructor(config) {
    this.jwks = [];
    this.config = {
      ...config,
      domain: this.ensureHttps(config.domain),
      callbackUrl: this.ensureHttps(config.callbackUrl)
    };
  }
  ensureHttps(url) {
    if (url.startsWith("http://") || url.startsWith("https://")) {
      return url;
    }
    return `https://${url}`;
  }
  normalizeUrl(url) {
    return url.endsWith("/") ? url.slice(0, -1) : url;
  }
  decodeToken(token) {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid token format");
    }
    const payload = parts[1];
    const paddedPayload = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decodedPayload = atob(paddedPayload);
    return JSON.parse(decodedPayload);
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
      console.error(
        "Failed to exchange code for tokens. Status:",
        response.status,
        "Error:",
        errorText
      );
      throw new Error(`Failed to exchange code for tokens: ${errorText}`);
    }
    const tokens = await response.json();
    if (!this.isValidTokenResponse(tokens)) {
      console.error("Invalid token response:", tokens);
      throw new Error("Invalid token response");
    }
    console.log("Received tokens:", JSON.stringify(tokens, null, 2));
    if (tokens.id_token) {
      const decodedIdToken = this.decodeToken(tokens.id_token);
      console.log("Decoded ID Token:", JSON.stringify(decodedIdToken, null, 2));
    } else {
      console.warn("No ID token received in the token response");
    }
    return tokens;
  }
  isValidTokenResponse(tokens) {
    return typeof tokens === "object" && typeof tokens.access_token === "string" && typeof tokens.id_token === "string" && typeof tokens.expires_in === "number" && typeof tokens.token_type === "string" && (tokens.refresh_token === void 0 || typeof tokens.refresh_token === "string");
  }
  async verifyToken(token) {
    if (this.jwks.length === 0) {
      await this.fetchJwks();
    }
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid token format");
    }
    const [headerB64, payloadB64, signature] = parts;
    const base64UrlDecode = (str) => {
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) {
        str += "=";
      }
      return atob(str);
    };
    let decodedHeader;
    let decodedPayload;
    try {
      decodedHeader = JSON.parse(base64UrlDecode(headerB64));
      decodedPayload = JSON.parse(base64UrlDecode(payloadB64));
    } catch (error) {
      console.error("Error decoding token:", error);
      throw new Error("Invalid token encoding");
    }
    console.log("Decoded payload:", decodedPayload);
    console.log("Expected issuer:", this.config.domain);
    console.log("Expected audience:", this.config.clientId);
    const kid = decodedHeader.kid;
    if (!kid) {
      throw new Error('Token header is missing "kid" property');
    }
    const key = this.jwks.find((k) => "kid" in k && k.kid === kid);
    if (!key) {
      throw new Error("Unable to find a matching key in the JWKS");
    }
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      key,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const encoder = new TextEncoder();
    const data = encoder.encode(`${headerB64}.${payloadB64}`);
    const signatureArray = Uint8Array.from(
      base64UrlDecode(signature),
      (c) => c.charCodeAt(0)
    );
    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      signatureArray,
      data
    );
    if (!isValid) {
      throw new Error("Invalid token signature");
    }
    const now = Math.floor(Date.now() / 1e3);
    if (typeof decodedPayload.exp === "number" && decodedPayload.exp < now) {
      throw new Error("Token has expired");
    }
    if (typeof decodedPayload.nbf === "number" && decodedPayload.nbf > now) {
      throw new Error("Token is not yet valid");
    }
    if (this.normalizeUrl(decodedPayload.iss) !== this.normalizeUrl(this.config.domain)) {
      console.error("Token issuer mismatch:", {
        tokenIssuer: decodedPayload.iss,
        expectedIssuer: this.config.domain
      });
      throw new Error("Token issuer is invalid");
    }
    const tokenAudience = decodedPayload.aud;
    const tokenAzp = decodedPayload.azp;
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
    return { payload: decodedPayload };
  }
  async fetchJwks() {
    const response = await fetch(`${this.config.domain}/.well-known/jwks.json`);
    if (!response.ok) {
      throw new Error("Failed to fetch JWKS");
    }
    const jwks = await response.json();
    this.jwks = jwks.keys;
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
      console.error(
        "Failed to refresh token. Status:",
        response.status,
        "Error:",
        errorText
      );
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
import { NextRequest, NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";

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
function constructBaseUrl(req) {
  let baseUrl;
  const referer = req.headers.get("referer");
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      baseUrl = `${refererUrl.protocol}//${refererUrl.host}`;
    } catch (error) {
      console.error("Error parsing referer:", error);
    }
  }
  if (!baseUrl) {
    const protocol = req.headers.get("x-forwarded-proto") || "https";
    const host = req.headers.get("x-forwarded-host") || req.headers.get("host") || "localhost";
    baseUrl = `${protocol}://${host}`;
  }
  console.log("Constructed Base URL:", baseUrl);
  return baseUrl;
}
function constructFullUrl(req, path) {
  const baseUrl = constructBaseUrl(req);
  const fullUrl = new URL(path, baseUrl).toString();
  console.log("Constructed Full URL:", fullUrl);
  return fullUrl;
}

// src/withAuth.ts
function withAuth(handler) {
  return async (req) => {
    const cloudflareContext = await getCloudflareContext();
    const context = createAuth0CloudflareContext(cloudflareContext);
    const { env } = context;
    const auth0Client = new Auth0Client({
      domain: env.AUTH0_DOMAIN,
      clientId: env.AUTH0_CLIENT_ID,
      clientSecret: env.AUTH0_CLIENT_SECRET,
      callbackUrl: constructFullUrl(req, "/api/auth/callback"),
      audience: env.AUTH0_AUDIENCE
    });
    const accessToken = req.cookies.get("access_token")?.value;
    if (!accessToken) {
      return NextResponse.redirect(constructFullUrl(req, "/api/auth/login"));
    }
    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq = new NextRequest(req, {
        headers: req.headers
      });
      authenticatedReq.auth = {
        token: accessToken,
        payload: verifyResult.payload
      };
      return handler(authenticatedReq);
    } catch (error) {
      console.error("Error verifying token:", error);
      return NextResponse.redirect(constructFullUrl(req, "/api/auth/login"));
    }
  };
}

// src/authUtils.ts
import { NextResponse as NextResponse2 } from "next/server";
import { getCloudflareContext as getCloudflareContext2 } from "@opennextjs/cloudflare";
async function handleLogin(req) {
  const cloudflareContext = await getCloudflareContext2();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  console.log("Auth0 Configuration:", {
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    callbackUrl: constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE
  });
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE
  });
  try {
    const state = crypto.randomUUID();
    const authorizationUrl = await auth0Client.getAuthorizationUrl(state);
    console.log("Login - Authorization URL:", authorizationUrl);
    const response = NextResponse2.redirect(authorizationUrl);
    response.cookies.set("auth_state", state, { httpOnly: true, secure: true });
    return response;
  } catch (error) {
    console.error("Error in handleLogin:", error);
    return NextResponse2.redirect(constructFullUrl(req, "/auth/error"));
  }
}
async function handleCallback(req) {
  const cloudflareContext = await getCloudflareContext2();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE
  });
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");
  console.log("Callback - Received params:", {
    code,
    state,
    error,
    errorDescription
  });
  const storedState = req.cookies.get("auth_state")?.value;
  if (error) {
    console.error("Auth0 error:", error, errorDescription);
    return NextResponse2.redirect(constructFullUrl(req, "/auth/error"));
  }
  if (!code || !state || !storedState || state !== storedState) {
    console.error("Invalid callback parameters");
    return NextResponse2.redirect(constructFullUrl(req, "/api/auth/login"));
  }
  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);
    const userInfo = await auth0Client.getUserInfo(tokens.access_token);
    const response = NextResponse2.redirect(constructFullUrl(req, "/"));
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
    response.cookies.set("user_info", JSON.stringify(userInfo), {
      httpOnly: true,
      secure: true
    });
    return response;
  } catch (error2) {
    console.error("Error during callback:", error2);
    return NextResponse2.redirect(constructFullUrl(req, "/auth/error"));
  }
}
async function handleLogout(req) {
  const cloudflareContext = await getCloudflareContext2();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE
  });
  const returnTo = constructFullUrl(req, "/");
  const logoutUrl = auth0Client.getLogoutUrl(returnTo);
  const response = NextResponse2.redirect(logoutUrl);
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  response.cookies.delete("user_info");
  return response;
}

// src/handleAuth.ts
import { NextResponse as NextResponse3 } from "next/server";

// src/getSession.ts
import { getCloudflareContext as getCloudflareContext3 } from "@opennextjs/cloudflare";
async function getSession(req) {
  const cloudflareContext = await getCloudflareContext3();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: constructFullUrl(req, "/api/auth/callback"),
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
          return NextResponse3.json(session.user);
        }
        return new NextResponse3("Unauthorized", { status: 401 });
      default:
        return new NextResponse3("Not Found", { status: 404 });
    }
  };
}
export {
  Auth0Client,
  createAuth0CloudflareContext,
  getSession,
  handleAuth,
  handleCallback,
  handleLogin,
  handleLogout,
  withAuth
};
