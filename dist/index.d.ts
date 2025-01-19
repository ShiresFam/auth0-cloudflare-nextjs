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
interface JWTPayload {
    [key: string]: string | number | boolean | null | undefined;
}
interface UserInfo {
    sub: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    middle_name?: string;
    nickname?: string;
    preferred_username?: string;
    profile?: string;
    picture?: string;
    website?: string;
    email?: string;
    email_verified?: boolean;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    phone_number?: string;
    phone_number_verified?: boolean;
    address?: {
        country?: string;
    };
    updated_at?: string;
    [key: string]: any;
}
declare class Auth0Client {
    private config;
    constructor(config: Auth0Config);
    private ensureHttps;
    private ensureCorrectProtocol;
    private normalizeUrl;
    getAuthorizationUrl(state: string): Promise<string>;
    exchangeCodeForTokens(code: string): Promise<TokenResponse>;
    private isValidTokenResponse;
    verifyToken(token: string): Promise<{
        payload: JWTPayload;
    }>;
    refreshToken(refreshToken: string): Promise<TokenResponse>;
    getUserInfo(accessToken: string): Promise<UserInfo>;
    getLogoutUrl(returnTo: string): string;
}

interface Auth0Env {
    AUTH0_DOMAIN: string;
    AUTH0_CLIENT_ID: string;
    AUTH0_CLIENT_SECRET: string;
    AUTH0_CALLBACK_URL: string;
    AUTH0_AUDIENCE?: string;
    AUTH0_BASE_URL?: string;
    DISABLE_SECURE_COOKIES?: string;
}
type Auth0CloudflareEnv = CloudflareContext['env'] & Auth0Env;
interface Auth0CloudflareContext extends Omit<CloudflareContext, 'env'> {
    env: Auth0CloudflareEnv;
}
interface AuthenticatedNextRequest extends NextRequest {
    auth: {
        token: string;
        payload: JWTPayload;
    };
}
type AuthenticatedHandler = (request: AuthenticatedNextRequest) => Promise<NextResponse>;

declare function withAuth(handler: AuthenticatedHandler): (req: NextRequest) => Promise<NextResponse<unknown>>;

declare function handleLogin(req: NextRequest): Promise<NextResponse>;
declare function handleCallback(req: NextRequest): Promise<NextResponse>;
declare function handleLogout(req: NextRequest): Promise<NextResponse>;

declare function createAuth0CloudflareContext(baseContext: CloudflareContext): Auth0CloudflareContext;

declare function handleAuth(): (req: NextRequest) => Promise<NextResponse<any>>;

declare function getSession(req: NextRequest): Promise<{
    user: any;
    accessToken: string;
} | null>;

export { Auth0Client, Auth0CloudflareContext, Auth0CloudflareEnv, Auth0Config, AuthenticatedHandler, AuthenticatedNextRequest, JWTPayload, TokenResponse, createAuth0CloudflareContext, getSession, handleAuth, handleCallback, handleLogin, handleLogout, withAuth };
