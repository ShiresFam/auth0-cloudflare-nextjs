import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client, Auth0Config } from './auth0Client';

export type CloudflareEnv = Auth0Config;

export interface AuthenticatedRequest extends NextRequest {
  auth: {
    token: string;
    payload: any; // You can replace 'any' with a more specific type if needed
  };
}

export type AuthenticatedHandler<T extends CloudflareEnv> = (
  req: AuthenticatedRequest,
  env: T
) => Promise<NextResponse>;

export function withAuth<T extends CloudflareEnv>(
  handler: AuthenticatedHandler<T>
): (req: NextRequest, context: { env: T }) => Promise<NextResponse> {
  return async (req: NextRequest, context: { env: T }) => {
    const { env } = context;

    const auth0Client = new Auth0Client(env);

    const accessToken = req.cookies.get('access_token')?.value;

    if (!accessToken) {
      return NextResponse.redirect(new URL('/api/login', req.url));
    }

    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq: AuthenticatedRequest = Object.assign(req, {
        auth: {
          token: accessToken,
          payload: verifyResult.payload,
        },
      });
      return handler(authenticatedReq, env);
    } catch (error) {
      // Token is invalid or expired
      const refreshToken = req.cookies.get('refresh_token')?.value;

      if (refreshToken) {
        try {
          const newTokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(newTokens.access_token);
          const authenticatedReq: AuthenticatedRequest = Object.assign(req, {
            auth: {
              token: newTokens.access_token,
              payload: verifyResult.payload,
            },
          });
          const response = await handler(authenticatedReq, env);

          response.cookies.set('access_token', newTokens.access_token, { httpOnly: true, secure: true });
          if (newTokens.refresh_token) {
            response.cookies.set('refresh_token', newTokens.refresh_token, { httpOnly: true, secure: true });
          }

          return response;
        } catch (refreshError) {
          // Refresh token is invalid or expired
          return NextResponse.redirect(new URL('/api/login', req.url));
        }
      } else {
        return NextResponse.redirect(new URL('/api/login', req.url));
      }
    }
  };
}

