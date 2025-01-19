import {jwtDecode} from "jwt-decode";
import type { JWTPayload } from "./types";

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

// export interface JWTPayload {
//   [key: string]: string | number | boolean | null | undefined;
// }

export interface UserInfo {
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

export class Auth0Client {
  private config: Auth0Config;

  constructor(config: Auth0Config) {
    this.config = {
      ...config,
      domain: this.ensureHttps(config.domain),
      callbackUrl: this.ensureCorrectProtocol(config.callbackUrl),
    };
  }

  private ensureHttps(url: string): string {
    if (url.startsWith("http://") || url.startsWith("https://")) {
      return url;
    }
    return `https://${url}`;
  }

  private ensureCorrectProtocol(url: string): string {
    const urlObject = new URL(url);
    if (urlObject.hostname === 'localhost' || urlObject.hostname.includes('127.0.0.1')) {
      urlObject.protocol = 'http:';
    } else {
      urlObject.protocol = 'https:';
    }
    return urlObject.toString();
  }

  private normalizeUrl(url: string): string {
    return url.endsWith("/") ? url.slice(0, -1) : url;
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

    const authorizationUrl = `${this.config.domain}/authorize?${params.toString()}`;
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


    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Failed to exchange code for tokens. Status:", response.status, "Error:", errorText);
      throw new Error(`Failed to exchange code for tokens: ${errorText}`);
    }

    const tokens = await response.json() as TokenResponse;

    if (!this.isValidTokenResponse(tokens)) {
      console.error("Invalid token response:", tokens);
      throw new Error("Invalid token response");
    }

    
    // if (tokens.id_token) {
    //   const decodedIdToken = jwtDecode(tokens.id_token);
    //   console.log("Decoded ID Token:", JSON.stringify(decodedIdToken, null, 2));
    // } else {
    //   console.warn("No ID token received in the token response");
    // }

    return tokens;
  }

  private isValidTokenResponse(tokens: unknown): tokens is TokenResponse {
    return (
      typeof tokens === 'object' &&
      tokens !== null &&
      'access_token' in tokens &&
      typeof tokens.access_token === 'string' &&
      'id_token' in tokens &&
      typeof tokens.id_token === 'string' &&
      'expires_in' in tokens &&
      typeof tokens.expires_in === 'number' &&
      'token_type' in tokens &&
      typeof tokens.token_type === 'string' &&
      (!('refresh_token' in tokens) || typeof tokens.refresh_token === 'string')
    );
  }

  async verifyToken(token: string): Promise<{ payload: JWTPayload }> {
    try {
      const decodedToken = jwtDecode(token) as JWTPayload;

      // Verify token claims
      const now = Math.floor(Date.now() / 1000);
      if (typeof decodedToken.exp === "number" && decodedToken.exp < now) {
        throw new Error("Token has expired");
      }
      if (typeof decodedToken.nbf === "number" && decodedToken.nbf > now) {
        throw new Error("Token is not yet valid");
      }
      if (
        this.normalizeUrl(decodedToken.iss as string) !==
        this.normalizeUrl(this.config.domain)
      ) {
        console.error("Token issuer mismatch:", {
          tokenIssuer: decodedToken.iss,
          expectedIssuer: this.config.domain,
        });
        throw new Error("Token issuer is invalid");
      }

      // Check if the audience is an array or a string
      const tokenAudience = decodedToken.aud;
      const tokenAzp = decodedToken.azp;

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


      return { payload: decodedToken };
    } catch (error) {
      console.error("Error verifying token:", error);
      throw new Error("Invalid token");
    }
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
      console.error("Failed to refresh token. Status:", response.status, "Error:", errorText);
      throw new Error(`Failed to refresh token: ${errorText}`);
    }

    const tokens = await response.json() as TokenResponse;

    if (!this.isValidTokenResponse(tokens)) {
      console.error("Invalid token response:", tokens);
      throw new Error("Invalid token response");
    }

    return tokens;
  }

  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const response = await fetch(`${this.config.domain}/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user info');
    }

    const userInfo: UserInfo = await response.json();
    return userInfo;
  }

  getLogoutUrl(returnTo: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      returnTo: returnTo
    });

    return `${this.config.domain}/v2/logout?${params.toString()}`;
  }
}

