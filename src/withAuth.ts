import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client } from './auth0Client';
import { AuthenticatedNextRequest, AuthenticatedHandler, Auth0CloudflareContext } from './types';
import { getCloudflareContext } from '@opennextjs/cloudflare';
import { createAuth0CloudflareContext } from './contextUtils';
import { constructFullUrl } from './urlUtils';

export function withAuth(handler: AuthenticatedHandler) {
  return async (req: NextRequest) => {
    const cloudflareContext = await getCloudflareContext();
    const context = createAuth0CloudflareContext(cloudflareContext);
    const { env } = context;

    const auth0Client = new Auth0Client({
      domain: env.AUTH0_DOMAIN,
      clientId: env.AUTH0_CLIENT_ID,
      clientSecret: env.AUTH0_CLIENT_SECRET,
      callbackUrl: await constructFullUrl(req, '/api/auth/callback'),
      audience: env.AUTH0_AUDIENCE,
    });

    const accessToken = req.cookies.get('access_token')?.value;

    if (!accessToken) {
      return NextResponse.redirect(await constructFullUrl(req, '/api/auth/login'));
    }

    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq = new NextRequest(req, {
        headers: req.headers,
      }) as AuthenticatedNextRequest;
      authenticatedReq.auth = {
        token: accessToken,
        payload: verifyResult.payload,
      };
      return handler(authenticatedReq);
    } catch (error) {
      console.error('Error verifying token:', error);
      
      // Try to refresh the token if a refresh token is available
      const refreshToken = req.cookies.get('refresh_token')?.value;
      if (refreshToken) {
        try {
          const tokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(tokens.access_token);
          const authenticatedReq = new NextRequest(req, {
            headers: req.headers,
          }) as AuthenticatedNextRequest;
          authenticatedReq.auth = {
            token: tokens.access_token,
            payload: verifyResult.payload,
          };

          const response = await handler(authenticatedReq);

          // Update the cookies with the new tokens
          const secureCookie = env.DISABLE_SECURE_COOKIES !== 'true';
          response.cookies.set('access_token', tokens.access_token, {
            httpOnly: true,
            secure: secureCookie,
          });
          if (tokens.refresh_token) {
            response.cookies.set('refresh_token', tokens.refresh_token, {
              httpOnly: true,
              secure: secureCookie,
            });
          }

          return response;
        } catch (refreshError) {
          console.error('Error refreshing token:', refreshError);
        }
      }

      return NextResponse.redirect(await constructFullUrl(req, '/api/auth/login'));
    }
  };
}

