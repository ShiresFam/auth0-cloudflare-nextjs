import * as jose from 'jose';
import jose__default, { JWTPayload as JWTPayload$1 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';
import { CloudflareContext } from '@opennextjs/cloudflare';
import * as react_jsx_runtime from 'react/jsx-runtime';
import React from 'react';

interface Auth0Config {
    domain: string;
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    audience?: string;
}
interface TokenResponse {
    access_token: string;
    id_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: string;
}
interface JWTPayload extends jose__default.JWTPayload {
    email?: string;
    name?: string;
}
declare class Auth0Client {
    protected config: Auth0Config;
    protected jwksClient: ReturnType<typeof jose__default.createRemoteJWKSet>;
    constructor(config: Auth0Config);
    getAuthorizationUrl(state: string): Promise<string>;
    exchangeCodeForTokens(code: string): Promise<TokenResponse>;
    verifyToken(token: string): Promise<jose__default.JWTVerifyResult & {
        payload: JWTPayload;
    }>;
    refreshToken(refreshToken: string): Promise<TokenResponse>;
}

interface Auth0Env {
    AUTH0_DOMAIN: string;
    AUTH0_CLIENT_ID: string;
    AUTH0_CLIENT_SECRET: string;
    AUTH0_CALLBACK_URL: string;
    AUTH0_AUDIENCE?: string;
}
type Auth0CloudflareEnv = CloudflareContext["env"] & Auth0Env;
interface Auth0CloudflareContext extends Omit<CloudflareContext, "env"> {
    env: Auth0CloudflareEnv;
}
interface AuthenticatedNextRequest extends NextRequest {
    auth: {
        token: string;
        payload: JWTPayload$1;
    };
}
type AuthenticatedHandler = (request: AuthenticatedNextRequest, context: Auth0CloudflareContext) => Promise<Response>;

declare function withAuth(handler: AuthenticatedHandler): (req: NextRequest, context: Auth0CloudflareContext) => Promise<Response>;

declare function handleLogin(req: NextRequest, context: CloudflareContext): Promise<NextResponse>;
declare function handleCallback(req: NextRequest, context: CloudflareContext): Promise<NextResponse>;
declare function handleLogout(req: NextRequest): Promise<NextResponse>;

declare function createAuth0CloudflareContext(baseContext: CloudflareContext): Auth0CloudflareContext;

declare function handleAuth(): (req: NextRequest, context: CloudflareContext) => Promise<NextResponse<unknown>>;

declare function getSession(req: NextRequest, context: CloudflareContext): Promise<{
    user: jose.JWTPayload & JWTPayload;
    accessToken: string;
} | null>;

interface Auth0User {
    name?: string;
    email?: string;
    picture?: string;
    [key: string]: any;
}
interface Auth0ContextType {
    user: Auth0User | null;
    error: Error | null;
    isLoading: boolean;
}
declare function UserProvider({ children }: {
    children: React.ReactNode;
}): react_jsx_runtime.JSX.Element;
declare function useUser(): Auth0ContextType;

export { Auth0Client, Auth0CloudflareContext, Auth0CloudflareEnv, Auth0Config, AuthenticatedHandler, AuthenticatedNextRequest, JWTPayload, TokenResponse, UserProvider, createAuth0CloudflareContext, getSession, handleAuth, handleCallback, handleLogin, handleLogout, useUser, withAuth };
