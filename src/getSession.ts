import { NextRequest } from 'next/server';
import { Auth0Client } from './auth0Client';
import { createAuth0CloudflareContext, getCompatibleCloudflareContext } from './contextUtils';
import { cookies } from 'next/headers';

async function getCompatibleCookieStore() {
  try {
    // Next.js 15 approach - cookies() is async
    return await cookies();
  } catch (error) {
    try {
      // Next.js 14 approach - cookies() is synchronous
      return cookies();
    } catch (fallbackError) {
      console.error('Failed to get cookie store:', fallbackError);
      throw fallbackError;
    }
  }
}

export async function getSessionFromRequest(request: NextRequest) {
  const cloudflareContext = await getCompatibleCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE,
  });

  const accessToken = request.cookies.get("access_token")?.value;
  const userInfoCookie = request.cookies.get("user_info")?.value;

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
    console.error("Error verifying token:", error);
    return null;
  }
}

export async function getServerSession() {
  const cloudflareContext = await getCompatibleCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE,
  });

  const cookieStore = await getCompatibleCookieStore();
  const accessToken = cookieStore.get("access_token")?.value;
  const userInfoCookie = cookieStore.get("user_info")?.value;

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
    console.error("Error verifying token:", error);
    return null;
  }
}
