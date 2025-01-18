import * as jose from "jose";

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
  // Add any custom claims you expect in your JWT
  email?: string;
  name?: string;
}

export class Auth0Client {
  protected config: Auth0Config;
  protected jwksClient: ReturnType<typeof jose.createRemoteJWKSet>;

  constructor(config: Auth0Config) {
    // Normalize the domain to ensure it includes a protocol
    let domain = config.domain;
    if (!/^https?:\/\//i.test(domain)) {
      domain = `https://${domain}`;
    }
    this.config = { ...config, domain };

    this.jwksClient = jose.createRemoteJWKSet(
      new URL(`${domain}/.well-known/jwks.json`)
    );
  }

  async getAuthorizationUrl(state: string): Promise<string> {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      scope: "openid profile email",
      state,
    });

    if (this.config.audience) {
      params.append("audience", this.config.audience);
    }

    return `${this.config.domain}/authorize?${params.toString()}`;
  }

  async exchangeCodeForTokens(code: string): Promise<TokenResponse> {
    const response = await fetch(`${this.config.domain}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        redirect_uri: this.config.callbackUrl,
      }),
    });

    if (!response.ok) {
      throw new Error("Failed to exchange code for tokens");
    }

    return response.json();
  }

  async verifyToken(
    token: string
  ): Promise<jose.JWTVerifyResult & { payload: JWTPayload }> {
    return jose.jwtVerify(token, this.jwksClient, {
      issuer: `${this.config.domain}/`,
      audience: this.config.clientId,
    }) as Promise<jose.JWTVerifyResult & { payload: JWTPayload }>;
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const response = await fetch(`${this.config.domain}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error("Failed to refresh token");
    }

    return response.json();
  }
}
