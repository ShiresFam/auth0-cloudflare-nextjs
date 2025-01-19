import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client } from './auth0Client';
import { AuthenticatedNextRequest, AuthenticatedHandler, Auth0CloudflareContext, JWTPayload } from './types';
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
      return await handleAuthenticatedRequest(req, accessToken, verifyResult.payload, handler);
    } catch (error) {
      console.error('Error verifying token:', error);
      return await handleTokenRefresh(req, auth0Client, env, handler);
    }
  };
}

async function handleAuthenticatedRequest(
  req: NextRequest, 
  accessToken: string, 
  payload: JWTPayload, 
  handler: AuthenticatedHandler
) {
  const authenticatedReq = createAuthenticatedRequest(req, accessToken, payload);
  return handler(authenticatedReq);
}

async function handleTokenRefresh(
  req: NextRequest, 
  auth0Client: Auth0Client, 
  env: Auth0CloudflareContext['env'], 
  handler: AuthenticatedHandler
) {
  const refreshToken = req.cookies.get('refresh_token')?.value;
  if (refreshToken) {
    try {
      const tokens = await auth0Client.refreshToken(refreshToken);
      const verifyResult = await auth0Client.verifyToken(tokens.access_token);
      const authenticatedReq = createAuthenticatedRequest(req, tokens.access_token, verifyResult.payload);
      const response = await handler(authenticatedReq);
      return updateResponseWithNewTokens(response, tokens, env);
    } catch (refreshError) {
      console.error('Error refreshing token:', refreshError);
    }
  }
  return NextResponse.redirect(await constructFullUrl(req, '/api/auth/login'));
}

function createAuthenticatedRequest(req: NextRequest, accessToken: string, payload: JWTPayload): AuthenticatedNextRequest {
  const authenticatedReq = new NextRequest(req, {
    headers: new Headers(req.headers),
  }) as AuthenticatedNextRequest;
  authenticatedReq.auth = { token: accessToken, payload };
  authenticatedReq.headers.set('Authorization', `Bearer ${accessToken}`);
  return authenticatedReq;
}

function updateResponseWithNewTokens(response: NextResponse, tokens: { access_token: string, refresh_token?: string }, env: Auth0CloudflareContext['env']) {
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
}

