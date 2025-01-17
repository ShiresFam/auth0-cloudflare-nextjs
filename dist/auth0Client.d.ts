import jose from 'jose';
export interface Auth0Config {
    domain: string;
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    audience?: string;
}
export interface TokenResponse {
    access_token: string;
    id_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: string;
}
export interface JWTPayload extends jose.JWTPayload {
    email?: string;
    name?: string;
}
export declare class Auth0Client {
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
