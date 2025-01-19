import { CloudflareContext } from "@opennextjs/cloudflare";
import { NextRequest } from "next/server";
import { JWTPayload } from "jose";

export interface Auth0Env {
  AUTH0_DOMAIN: string;
  AUTH0_CLIENT_ID: string;
  AUTH0_CLIENT_SECRET: string;
  AUTH0_CALLBACK_URL: string;
  AUTH0_AUDIENCE?: string;
}

export type Auth0CloudflareEnv = CloudflareContext["env"] & Auth0Env;

export interface Auth0CloudflareContext extends Omit<CloudflareContext, "env"> {
  env: Auth0CloudflareEnv;
}

export interface Auth0Config {
  domain: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
  audience?: string;
}

export interface AuthenticatedNextRequest extends NextRequest {
  auth: {
    token: string;
    payload: JWTPayload;
  };
}

export type AuthenticatedHandler = (
  request: AuthenticatedNextRequest
) => Promise<Response>;
