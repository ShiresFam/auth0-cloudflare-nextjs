import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client, Auth0Config } from './auth0Client';

export async function handleLogin(req: NextRequest, env: Auth0Config): Promise<NextResponse> {
  const auth0Client = new Auth0Client(env);

  const state = crypto.randomUUID();
  const authorizationUrl = await auth0Client.getAuthorizationUrl(state);

  const response = NextResponse.redirect(authorizationUrl);
  response.cookies.set('auth_state', state, { httpOnly: true, secure: true });

  return response;
}

export async function handleCallback(req: NextRequest, env: Auth0Config): Promise<NextResponse> {
  const auth0Client = new Auth0Client(env);

  const { searchParams } = new URL(req.url);
  const code = searchParams.get('code');
  const state = searchParams.get('state');

  const storedState = req.cookies.get('auth_state')?.value;

  if (!code || !state || !storedState || state !== storedState) {
    return NextResponse.redirect(new URL('/api/login', req.url));
  }

  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);

    const response = NextResponse.redirect(new URL('/', req.url));

    response.cookies.set('access_token', tokens.access_token, { httpOnly: true, secure: true });
    if (tokens.refresh_token) {
      response.cookies.set('refresh_token', tokens.refresh_token, { httpOnly: true, secure: true });
    }
    response.cookies.delete('auth_state');

    return response;
  } catch (error) {
    console.error('Error during callback:', error);
    return NextResponse.redirect(new URL('/api/login', req.url));
  }
}

export function handleLogout(req: NextRequest): NextResponse {
  const response = NextResponse.redirect(new URL('/', req.url));

  response.cookies.delete('access_token');
  response.cookies.delete('refresh_token');

  return response;
}

