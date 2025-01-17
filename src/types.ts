import { Auth0Config } from './auth0Client';
import { NextRequest } from 'next/server';
import { JWTPayload } from 'jose';

export interface CloudflareEnv extends Auth0Config {
  [key: string]: any;
}

export interface AuthenticatedNextRequest extends NextRequest {
  auth: {
    token: string;
    payload: JWTPayload;
  };
}

export type AuthenticatedHandler = (
  request: AuthenticatedNextRequest,
  env: CloudflareEnv
) => Promise<Response>;

