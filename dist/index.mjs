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
import { NextResponse } from "next/server";
function withAuth(handler) {
  return async (req, context) => {
    const { env } = context;
    const auth0Client = new Auth0Client(env);
    const accessToken = req.cookies.get("access_token")?.value;
    if (!accessToken) {
      return NextResponse.redirect(new URL("/api/login", req.url));
    }
    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq = Object.assign(
        Object.create(Object.getPrototypeOf(req)),
        req,
        {
          auth: {
            token: accessToken,
            payload: verifyResult.payload
          }
        }
      );
      return handler(authenticatedReq, env);
    } catch (error) {
      const refreshToken = req.cookies.get("refresh_token")?.value;
      if (refreshToken) {
        try {
          const newTokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(newTokens.access_token);
          const authenticatedReq = Object.assign(
            Object.create(Object.getPrototypeOf(req)),
            req,
            {
              auth: {
                token: newTokens.access_token,
                payload: verifyResult.payload
              }
            }
          );
          const response = await handler(authenticatedReq, env);
          const nextResponse = NextResponse.json(
            await response.json(),
            {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers
            }
          );
          nextResponse.cookies.set("access_token", newTokens.access_token, { httpOnly: true, secure: true });
          if (newTokens.refresh_token) {
            nextResponse.cookies.set("refresh_token", newTokens.refresh_token, { httpOnly: true, secure: true });
          }
          return nextResponse;
        } catch (refreshError) {
          return NextResponse.redirect(new URL("/api/login", req.url));
        }
      } else {
        return NextResponse.redirect(new URL("/api/login", req.url));
      }
    }
  };
}

// src/authUtils.ts
import { NextResponse as NextResponse2 } from "next/server";
async function handleLogin(req, env) {
  const auth0Client = new Auth0Client(env);
  const state = crypto.randomUUID();
  const authorizationUrl = await auth0Client.getAuthorizationUrl(state);
  const response = NextResponse2.redirect(authorizationUrl);
  response.cookies.set("auth_state", state, { httpOnly: true, secure: true });
  return response;
}
async function handleCallback(req, env) {
  const auth0Client = new Auth0Client(env);
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
    response.cookies.set("access_token", tokens.access_token, { httpOnly: true, secure: true });
    if (tokens.refresh_token) {
      response.cookies.set("refresh_token", tokens.refresh_token, { httpOnly: true, secure: true });
    }
    response.cookies.delete("auth_state");
    return response;
  } catch (error) {
    console.error("Error during callback:", error);
    return NextResponse2.redirect(new URL("/api/login", req.url));
  }
}
function handleLogout(req) {
  const response = NextResponse2.redirect(new URL("/", req.url));
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  return response;
}
export {
  Auth0Client,
  handleCallback,
  handleLogin,
  handleLogout,
  withAuth
};
