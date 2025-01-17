import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client } from './auth0Client';
import { CloudflareEnv, AuthenticatedNextRequest, AuthenticatedHandler } from './types';

export function withAuth(handler: AuthenticatedHandler) {
  return async (req: NextRequest, context: { env: CloudflareEnv }) => {
    const { env } = context;

    const auth0Client = new Auth0Client(env);

    const accessToken = req.cookies.get('access_token')?.value;

    if (!accessToken) {
      return NextResponse.redirect(new URL('/api/login', req.url));
    }

    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq: AuthenticatedNextRequest = Object.assign(
        Object.create(Object.getPrototypeOf(req)),
        req,
        {
          auth: {
            token: accessToken,
            payload: verifyResult.payload,
          },
        }
      );
      return handler(authenticatedReq, env);
    } catch (error) {
      // Token is invalid or expired
      const refreshToken = req.cookies.get('refresh_token')?.value;

      if (refreshToken) {
        try {
          const newTokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(newTokens.access_token);
          const authenticatedReq: AuthenticatedNextRequest = Object.assign(
            Object.create(Object.getPrototypeOf(req)),
            req,
            {
              auth: {
                token: newTokens.access_token,
                payload: verifyResult.payload,
              },
            }
          );
          const response = await handler(authenticatedReq, env);

          // Create a new response based on the handler's response
          const nextResponse = NextResponse.json(
            await response.json(),
            {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers,
            }
          );

          // Set the new tokens as cookies
          nextResponse.cookies.set('access_token', newTokens.access_token, { httpOnly: true, secure: true });
          if (newTokens.refresh_token) {
            nextResponse.cookies.set('refresh_token', newTokens.refresh_token, { httpOnly: true, secure: true });
          }

          return nextResponse;
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

