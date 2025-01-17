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

  const state = crypto.randomUUID();
  const authorizationUrl = await auth0Client.getAuthorizationUrl(state);

  const response = NextResponse.redirect(authorizationUrl);
  response.cookies.set('auth_state', state, { httpOnly: true, secure: true });

  return response;
}

