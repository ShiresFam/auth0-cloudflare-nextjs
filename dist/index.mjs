// src/auth0Client.ts
import jose from "jose";
var Auth0Client = class {
  constructor(config) {
    this.config = config;
    this.jwksClient = jose.createRemoteJWKSet(new URL(`https://${config.domain}/.well-known/jwks.json`));
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
    return `https://${this.config.domain}/authorize?${params.toString()}`;
  }
  async exchangeCodeForTokens(code) {
    const response = await fetch(`https://${this.config.domain}/oauth/token`, {
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
      issuer: `https://${this.config.domain}/`,
      audience: this.config.clientId
    });
  }
  async refreshToken(refreshToken) {
    const response = await fetch(`https://${this.config.domain}/oauth/token`, {
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
import { NextRequest, NextResponse } from "next/server";
function withAuth(handler) {
  return async (req, context) => {
    const { env } = context;
    const auth0Client = new Auth0Client({
      domain: env.AUTH0_DOMAIN,
      clientId: env.AUTH0_CLIENT_ID,
      clientSecret: env.AUTH0_CLIENT_SECRET,
      callbackUrl: env.AUTH0_CALLBACK_URL,
      audience: env.AUTH0_AUDIENCE
    });
    const accessToken = req.cookies.get("access_token")?.value;
    if (!accessToken) {
      return NextResponse.redirect(new URL("/api/auth/login", req.url));
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
      return handler(authenticatedReq, context);
    } catch (error) {
      const refreshToken = req.cookies.get("refresh_token")?.value;
      if (refreshToken) {
        try {
          const newTokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(
            newTokens.access_token
          );
          const authenticatedReq = new NextRequest(req, {
            headers: req.headers
          });
          authenticatedReq.auth = {
            token: newTokens.access_token,
            payload: verifyResult.payload
          };
          const response = await handler(authenticatedReq, context);
          const nextResponse = NextResponse.json(
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
          return NextResponse.redirect(new URL("/api/auth/login", req.url));
        }
      } else {
        return NextResponse.redirect(new URL("/api/auth/login", req.url));
      }
    }
  };
}

// src/authUtils.ts
import { NextResponse as NextResponse2 } from "next/server";

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
  const state = crypto.randomUUID();
  const authorizationUrl = await auth0Client.getAuthorizationUrl(state);
  const response = NextResponse2.redirect(authorizationUrl);
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
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const storedState = req.cookies.get("auth_state")?.value;
  if (!code || !state || !storedState || state !== storedState) {
    return NextResponse2.redirect(new URL("/api/login", req.url));
  }
  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);
    const response = NextResponse2.redirect(new URL("/", req.url));
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
    return NextResponse2.redirect(new URL("/api/login", req.url));
  }
}
async function handleLogout(req) {
  const response = NextResponse2.redirect(new URL("/", req.url));
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  return response;
}

// src/handleAuth.ts
import { NextResponse as NextResponse3 } from "next/server";

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

// src/handleAuth.ts
function handleAuth() {
  return async (req, context) => {
    const { pathname } = new URL(req.url);
    switch (pathname) {
      case "/api/auth/login":
        return handleLogin(req, context);
      case "/api/auth/callback":
        return handleCallback(req, context);
      case "/api/auth/logout":
        return handleLogout(req);
      case "/api/auth/me":
        const session = await getSession(req, context);
        if (session?.user) {
          return NextResponse3.json(session.user);
        }
        return new NextResponse3("Unauthorized", { status: 401 });
      default:
        return new NextResponse3("Not Found", { status: 404 });
    }
  };
}

// src/client.tsx
import { createContext, useContext, useEffect, useState } from "react";
import { jsx } from "react/jsx-runtime";
var Auth0Context = createContext({
  user: null,
  error: null,
  isLoading: true
});
function UserProvider({ children }) {
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  useEffect(() => {
    async function loadUserFromAPI() {
      try {
        const res = await fetch("/api/auth/me");
        if (res.ok) {
          const userData = await res.json();
          setUser(userData);
        }
      } catch (e) {
        setError(e instanceof Error ? e : new Error("An error occurred"));
      } finally {
        setIsLoading(false);
      }
    }
    loadUserFromAPI();
  }, []);
  return /* @__PURE__ */ jsx(Auth0Context.Provider, { value: { user, error, isLoading }, children });
}
function useUser() {
  return useContext(Auth0Context);
}
export {
  Auth0Client,
  UserProvider,
  createAuth0CloudflareContext,
  getSession,
  handleAuth,
  handleCallback,
  handleLogin,
  handleLogout,
  useUser,
  withAuth
};
