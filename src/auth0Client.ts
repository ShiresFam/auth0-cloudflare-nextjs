import { Auth0Config } from "./types";

export interface TokenResponse {
  access_token: string;
  id_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

export interface JWTPayload {
  [key: string]: string | number | boolean | null | undefined;
}

interface JWKSResponse {
  keys: JsonWebKey[];
}

export class Auth0Client {
  private config: Auth0Config;
  private jwks: JsonWebKey[] = [];

  constructor(config: Auth0Config) {
    this.config = {
      ...config,
      domain: this.ensureHttps(config.domain),
      callbackUrl: this.ensureHttps(config.callbackUrl),
    };
  }

  private ensureHttps(url: string): string {
    if (url.startsWith("http://") || url.startsWith("https://")) {
      return url;
    }
    return `https://${url}`;
  }

  private normalizeUrl(url: string): string {
    return url.endsWith("/") ? url.slice(0, -1) : url;
  }

  private decodeToken(token: string): any {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid token format");
    }
    const payload = parts[1];
    const paddedPayload = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decodedPayload = atob(paddedPayload);
    return JSON.parse(decodedPayload);
  }

  async getAuthorizationUrl(state: string): Promise<string> {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      scope: "openid profile email name",
      state,
    });

    if (this.config.audience) {
      params.append("audience", this.config.audience);
    }

    const authorizationUrl = `${
      this.config.domain
    }/authorize?${params.toString()}`;
    console.log("Generated Authorization URL:", authorizationUrl);
    return authorizationUrl;
  }

  async exchangeCodeForTokens(code: string): Promise<TokenResponse> {
    const tokenUrl = `${this.config.domain}/oauth/token`;
    const body = JSON.stringify({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      redirect_uri: this.config.callbackUrl,
    });

    console.log("Exchanging code for tokens. Token URL:", tokenUrl);
    console.log("Request body:", body);

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(
        "Failed to exchange code for tokens. Status:",
        response.status,
        "Error:",
        errorText
      );
      throw new Error(`Failed to exchange code for tokens: ${errorText}`);
    }

    const tokens = (await response.json()) as TokenResponse;

    if (!this.isValidTokenResponse(tokens)) {
      console.error("Invalid token response:", tokens);
      throw new Error("Invalid token response");
    }

    console.log("Received tokens:", JSON.stringify(tokens, null, 2));

    if (tokens.id_token) {
      const decodedIdToken = this.decodeToken(tokens.id_token);
      console.log("Decoded ID Token:", JSON.stringify(decodedIdToken, null, 2));
    } else {
      console.warn("No ID token received in the token response");
    }

    return tokens;
  }

  private isValidTokenResponse(tokens: any): tokens is TokenResponse {
    return (
      typeof tokens === "object" &&
      typeof tokens.access_token === "string" &&
      typeof tokens.id_token === "string" &&
      typeof tokens.expires_in === "number" &&
      typeof tokens.token_type === "string" &&
      (tokens.refresh_token === undefined ||
        typeof tokens.refresh_token === "string")
    );
  }

  async verifyToken(token: string): Promise<{ payload: JWTPayload }> {
    if (this.jwks.length === 0) {
      await this.fetchJwks();
    }

    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid token format");
    }

    const [headerB64, payloadB64, signature] = parts;

    // Base64Url decode
    const base64UrlDecode = (str: string): string => {
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) {
        str += "=";
      }
      return atob(str);
    };

    let decodedHeader: { kid?: string };
    let decodedPayload: JWTPayload;

    try {
      decodedHeader = JSON.parse(base64UrlDecode(headerB64));
      decodedPayload = JSON.parse(base64UrlDecode(payloadB64));
    } catch (error) {
      console.error("Error decoding token:", error);
      throw new Error("Invalid token encoding");
    }

    console.log("Decoded payload:", decodedPayload);
    console.log("Expected issuer:", this.config.domain);
    console.log("Expected audience:", this.config.clientId);

    const kid = decodedHeader.kid;

    if (!kid) {
      throw new Error('Token header is missing "kid" property');
    }

    const key = this.jwks.find((k) => "kid" in k && k.kid === kid);
    if (!key) {
      throw new Error("Unable to find a matching key in the JWKS");
    }

    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      key,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(`${headerB64}.${payloadB64}`);
    const signatureArray = Uint8Array.from(base64UrlDecode(signature), (c) =>
      c.charCodeAt(0)
    );

    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      signatureArray,
      data
    );

    if (!isValid) {
      throw new Error("Invalid token signature");
    }

    // Verify token claims
    const now = Math.floor(Date.now() / 1000);
    if (typeof decodedPayload.exp === "number" && decodedPayload.exp < now) {
      throw new Error("Token has expired");
    }
    if (typeof decodedPayload.nbf === "number" && decodedPayload.nbf > now) {
      throw new Error("Token is not yet valid");
    }
    if (
      this.normalizeUrl(decodedPayload.iss as string) !==
      this.normalizeUrl(this.config.domain)
    ) {
      console.error("Token issuer mismatch:", {
        tokenIssuer: decodedPayload.iss,
        expectedIssuer: this.config.domain,
      });
      throw new Error("Token issuer is invalid");
    }

    // Check if the audience is an array or a string
    const tokenAudience = decodedPayload.aud;
    const tokenAzp = decodedPayload.azp;

    if (Array.isArray(tokenAudience)) {
      if (!tokenAudience.includes(this.config.clientId)) {
        if (tokenAzp !== this.config.clientId) {
          console.error("Token audience and azp mismatch:", {
            tokenAudience,
            tokenAzp,
            expectedAudience: this.config.clientId,
          });
          throw new Error("Token audience and authorized party are invalid");
        }
      }
    } else if (tokenAudience !== this.config.clientId) {
      if (tokenAzp !== this.config.clientId) {
        console.error("Token audience and azp mismatch:", {
          tokenAudience,
          tokenAzp,
          expectedAudience: this.config.clientId,
        });
        throw new Error("Token audience and authorized party are invalid");
      }
    }

    console.log("Token verification successful");

    return { payload: decodedPayload };
  }

  private async fetchJwks(): Promise<void> {
    const response = await fetch(`${this.config.domain}/.well-known/jwks.json`);
    if (!response.ok) {
      throw new Error("Failed to fetch JWKS");
    }
    const jwks = (await response.json()) as JWKSResponse;
    this.jwks = jwks.keys;
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
      const errorText = await response.text();
      console.error(
        "Failed to refresh token. Status:",
        response.status,
        "Error:",
        errorText
      );
      throw new Error(`Failed to refresh token: ${errorText}`);
    }

    const tokens = (await response.json()) as TokenResponse;

    if (!this.isValidTokenResponse(tokens)) {
      console.error("Invalid token response:", tokens);
      throw new Error("Invalid token response");
    }

    return tokens;
  }

  async getUserInfo(accessToken: string): Promise<any> {
    const response = await fetch(`${this.config.domain}/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error("Failed to fetch user info");
    }

    const userInfo = await response.json();
    console.log("User Info:", JSON.stringify(userInfo, null, 2));
    return userInfo;
  }

  getLogoutUrl(returnTo: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      returnTo: returnTo,
    });

    return `${this.config.domain}/v2/logout?${params.toString()}`;
  }
}
