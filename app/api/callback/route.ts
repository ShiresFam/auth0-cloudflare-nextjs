import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client } from '../../../lib/auth0';

export async function GET(req: NextRequest, context: { env: CloudflareEnv }) {
  const { env } = context;

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE,
  });

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

