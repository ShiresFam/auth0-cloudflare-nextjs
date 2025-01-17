import jose, { JWTPayload as JWTPayload$1 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';

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

interface CloudflareEnv extends Auth0Config {
    [key: string]: any;
}
interface AuthenticatedNextRequest extends NextRequest {
    auth: {
        token: string;
        payload: JWTPayload$1;
    };
}
type AuthenticatedHandler = (request: AuthenticatedNextRequest, env: CloudflareEnv) => Promise<Response>;

declare function withAuth(handler: AuthenticatedHandler): (req: NextRequest, context: {
    env: CloudflareEnv;
}) => Promise<Response>;

declare function handleLogin(req: NextRequest, env: Auth0Config): Promise<NextResponse>;
declare function handleCallback(req: NextRequest, env: Auth0Config): Promise<NextResponse>;
declare function handleLogout(req: NextRequest): NextResponse;

export { Auth0Client, Auth0Config, AuthenticatedHandler, AuthenticatedNextRequest, CloudflareEnv, JWTPayload, TokenResponse, handleCallback, handleLogin, handleLogout, withAuth };
