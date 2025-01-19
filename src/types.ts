import { CloudflareContext } from '@opennextjs/cloudflare';
import { NextRequest, NextResponse } from 'next/server';
import type { Auth0Config, JWTPayload } from './auth0Client';

export interface Auth0Env {
  AUTH0_DOMAIN: string;
  AUTH0_CLIENT_ID: string;
  AUTH0_CLIENT_SECRET: string;
  AUTH0_CALLBACK_URL: string;
  AUTH0_AUDIENCE?: string;
  AUTH0_BASE_URL?: string;
  DISABLE_SECURE_COOKIES?: string;
}

export type Auth0CloudflareEnv = CloudflareContext['env'] & Auth0Env;

export interface Auth0CloudflareContext extends Omit<CloudflareContext, 'env'> {
  env: Auth0CloudflareEnv;
}

export interface AuthenticatedNextRequest extends NextRequest {
  auth: {
    token: string;
    payload: JWTPayload;
  };
}

export type AuthenticatedHandler = (
  request: AuthenticatedNextRequest
) => Promise<NextResponse>;

