import { NextRequest } from 'next/server';
import { Auth0Client } from './auth0Client';
import { getCloudflareContext } from '@opennextjs/cloudflare';
import { createAuth0CloudflareContext } from './contextUtils';
import { constructFullUrl } from './urlUtils';

export async function getSession(req: NextRequest) {
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
  const userInfoCookie = req.cookies.get('user_info')?.value;

  if (!accessToken || !userInfoCookie) {
    return null;
  }

  try {
    await auth0Client.verifyToken(accessToken);
    const userInfo = JSON.parse(userInfoCookie);
    return {
      user: userInfo,
      accessToken,
    };
  } catch (error) {
    console.error('Error verifying token:', error);
    return null;
  }
}

