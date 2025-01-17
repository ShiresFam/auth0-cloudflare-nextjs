import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client } from '../lib/auth0';

interface CloudflareEnv {
  AUTH0_DOMAIN: string;
  AUTH0_CLIENT_ID: string;
  AUTH0_CLIENT_SECRET: string;
  AUTH0_CALLBACK_URL: string;
  AUTH0_AUDIENCE?: string;
}

export function withAuth(handler: (req: NextRequest, env: CloudflareEnv) => Promise<NextResponse>) {
  return async (req: NextRequest, context: { env: CloudflareEnv }) => {
    const { env } = context;

    const auth0Client = new Auth0Client({
      domain: env.AUTH0_DOMAIN,
      clientId: env.AUTH0_CLIENT_ID,
      clientSecret: env.AUTH0_CLIENT_SECRET,
      callbackUrl: env.AUTH0_CALLBACK_URL,
      audience: env.AUTH0_AUDIENCE,
    });

    const accessToken = req.cookies.get('access_token')?.value;

    if (!accessToken) {
      return NextResponse.redirect(new URL('/api/login', req.url));
    }

    try {
      await auth0Client.verifyToken(accessToken);
      return handler(req, env);
    } catch (error) {
      // Token is invalid or expired
      const refreshToken = req.cookies.get('refresh_token')?.value;

      if (refreshToken) {
        try {
          const newTokens = await auth0Client.refreshToken(refreshToken);
          const response = await handler(req, env);

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

