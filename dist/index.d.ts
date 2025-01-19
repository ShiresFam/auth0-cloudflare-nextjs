import { CloudflareContext } from '@opennextjs/cloudflare';
import { NextRequest, NextResponse } from 'next/server';
import { JWTPayload as JWTPayload$1 } from 'jose';

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
interface Auth0Config {
    domain: string;
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    audience?: string;
}
interface AuthenticatedNextRequest extends NextRequest {
    auth: {
        token: string;
        payload: JWTPayload$1;
    };
}
type AuthenticatedHandler = (request: AuthenticatedNextRequest) => Promise<Response>;

interface TokenResponse {
    access_token: string;
    id_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: string;
}
interface JWTPayload {
    [key: string]: string | number | boolean | null | undefined;
}
declare class Auth0Client {
    private config;
    private jwks;
    constructor(config: Auth0Config);
    private ensureHttps;
    private normalizeUrl;
    private decodeToken;
    getAuthorizationUrl(state: string): Promise<string>;
    exchangeCodeForTokens(code: string): Promise<TokenResponse>;
    private isValidTokenResponse;
    verifyToken(token: string): Promise<{
        payload: JWTPayload;
    }>;
    private fetchJwks;
    refreshToken(refreshToken: string): Promise<TokenResponse>;
    getUserInfo(accessToken: string): Promise<any>;
    getLogoutUrl(returnTo: string): string;
}

declare function withAuth(handler: AuthenticatedHandler): (req: NextRequest) => Promise<Response>;

declare function handleLogin(req: NextRequest): Promise<NextResponse>;
declare function handleCallback(req: NextRequest): Promise<NextResponse>;
declare function handleLogout(req: NextRequest): Promise<NextResponse>;

declare function createAuth0CloudflareContext(baseContext: CloudflareContext): Auth0CloudflareContext;

declare function handleAuth(): (req: NextRequest) => Promise<NextResponse<unknown>>;

declare function getSession(req: NextRequest): Promise<{
    user: JWTPayload;
    accessToken: string;
} | null>;

export { Auth0Client, Auth0CloudflareContext, Auth0CloudflareEnv, Auth0Config, AuthenticatedHandler, AuthenticatedNextRequest, JWTPayload, TokenResponse, createAuth0CloudflareContext, getSession, handleAuth, handleCallback, handleLogin, handleLogout, withAuth };
