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
  handleCallback: () => handleCallback,
  handleLogin: () => handleLogin,
  handleLogout: () => handleLogout,
  withAuth: () => withAuth
});
module.exports = __toCommonJS(src_exports);

// src/auth0Client.ts
var import_jose = __toESM(require("jose"));
var Auth0Client = class {
  constructor(config) {
    this.config = config;
    this.jwksClient = import_jose.default.createRemoteJWKSet(new URL(`https://${config.domain}/.well-known/jwks.json`));
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
    return import_jose.default.jwtVerify(token, this.jwksClient, {
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
var import_server = require("next/server");
function withAuth(handler) {
  return async (req, context) => {
    const { env } = context;
    const auth0Client = new Auth0Client(env);
    const accessToken = req.cookies.get("access_token")?.value;
    if (!accessToken) {
      return import_server.NextResponse.redirect(new URL("/api/login", req.url));
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
          const nextResponse = import_server.NextResponse.json(
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
          return import_server.NextResponse.redirect(new URL("/api/login", req.url));
        }
      } else {
        return import_server.NextResponse.redirect(new URL("/api/login", req.url));
      }
    }
  };
}

// src/authUtils.ts
var import_server2 = require("next/server");
async function handleLogin(req, env) {
  const auth0Client = new Auth0Client(env);
  const state = crypto.randomUUID();
  const authorizationUrl = await auth0Client.getAuthorizationUrl(state);
  const response = import_server2.NextResponse.redirect(authorizationUrl);
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
    return import_server2.NextResponse.redirect(new URL("/api/login", req.url));
  }
  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);
    const response = import_server2.NextResponse.redirect(new URL("/", req.url));
    response.cookies.set("access_token", tokens.access_token, { httpOnly: true, secure: true });
    if (tokens.refresh_token) {
      response.cookies.set("refresh_token", tokens.refresh_token, { httpOnly: true, secure: true });
    }
    response.cookies.delete("auth_state");
    return response;
  } catch (error) {
    console.error("Error during callback:", error);
    return import_server2.NextResponse.redirect(new URL("/api/login", req.url));
  }
}
function handleLogout(req) {
  const response = import_server2.NextResponse.redirect(new URL("/", req.url));
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  return response;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Auth0Client,
  handleCallback,
  handleLogin,
  handleLogout,
  withAuth
});
