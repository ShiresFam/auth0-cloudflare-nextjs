import * as jose from 'jose';
import { JWTPayload as JWTPayload$1 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';
import { CloudflareContext } from '@opennextjs/cloudflare';

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
interface JWTPayload extends jose.JWTPayload {
    email?: string;
    name?: string;
}
declare class Auth0Client {
    protected config: Auth0Config;
    protected jwksClient: ReturnType<typeof jose.createRemoteJWKSet>;
    constructor(config: Auth0Config);
    getAuthorizationUrl(state: string): Promise<string>;
    exchangeCodeForTokens(code: string): Promise<TokenResponse>;
    verifyToken(token: string): Promise<jose.JWTVerifyResult & {
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

declare function handleAuth(): (req: NextRequest) => Promise<NextResponse<unknown>>;

declare function getSession(req: NextRequest, context: CloudflareContext): Promise<{
    user: jose.JWTPayload & JWTPayload;
    accessToken: string;
} | null>;

export { Auth0Client, Auth0CloudflareContext, Auth0CloudflareEnv, Auth0Config, AuthenticatedHandler, AuthenticatedNextRequest, JWTPayload, TokenResponse, createAuth0CloudflareContext, getSession, handleAuth, handleCallback, handleLogin, handleLogout, withAuth };
