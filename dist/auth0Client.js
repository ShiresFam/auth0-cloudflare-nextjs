import jose from 'jose';
export class Auth0Client {
    constructor(config) {
        this.config = config;
        this.jwksClient = jose.createRemoteJWKSet(new URL(`https://${config.domain}/.well-known/jwks.json`));
    }
    async getAuthorizationUrl(state) {
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.callbackUrl,
            scope: 'openid profile email',
            state,
        });
        if (this.config.audience) {
            params.append('audience', this.config.audience);
        }
        return `https://${this.config.domain}/authorize?${params.toString()}`;
    }
    async exchangeCodeForTokens(code) {
        const response = await fetch(`https://${this.config.domain}/oauth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'authorization_code',
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                code,
                redirect_uri: this.config.callbackUrl,
            }),
        });
        if (!response.ok) {
            throw new Error('Failed to exchange code for tokens');
        }
        return response.json();
    }
    async verifyToken(token) {
        return jose.jwtVerify(token, this.jwksClient, {
            issuer: `https://${this.config.domain}/`,
            audience: this.config.clientId,
        });
    }
    async refreshToken(refreshToken) {
        const response = await fetch(`https://${this.config.domain}/oauth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                refresh_token: refreshToken,
            }),
        });
        if (!response.ok) {
            throw new Error('Failed to refresh token');
        }
        return response.json();
    }
}
