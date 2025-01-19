import { NextRequest, NextResponse } from "next/server";
import { Auth0Client } from "./auth0Client";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { createAuth0CloudflareContext } from "./contextUtils";
import {  constructFullUrl } from "./urlUtils";

export async function handleLogin(req: NextRequest): Promise<NextResponse> {
  const cloudflareContext = await getCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  const callbackUrl = await constructFullUrl(req, "/api/auth/callback");

  console.log('Auth0 Configuration:', {
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    callbackUrl: callbackUrl,
    audience: env.AUTH0_AUDIENCE,
  });

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: callbackUrl,
    audience: env.AUTH0_AUDIENCE,
  });

  try {
    const state = crypto.randomUUID();
    const authorizationUrl = await auth0Client.getAuthorizationUrl(state);

    console.log('Login - Authorization URL:', authorizationUrl);

    const response = NextResponse.redirect(authorizationUrl);
    const secureCookie = env.DISABLE_SECURE_COOKIES !== 'true';
    response.cookies.set("auth_state", state, { httpOnly: true, secure: secureCookie });

    return response;
  } catch (error) {
    console.error('Error in handleLogin:', error);
    return NextResponse.redirect(await constructFullUrl(req, '/auth/error'));
  }
}

export async function handleCallback(req: NextRequest): Promise<NextResponse> {
  const cloudflareContext = await getCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  const callbackUrl = await constructFullUrl(req, "/api/auth/callback");

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: callbackUrl,
    audience: env.AUTH0_AUDIENCE,
  });

  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");

  console.log('Callback - Received params:', { code, state, error, errorDescription });

  const storedState = req.cookies.get("auth_state")?.value;

  if (error) {
    console.error('Auth0 error:', error, errorDescription);
    return NextResponse.redirect(await constructFullUrl(req, '/auth/error'));
  }

  if (!code || !state || !storedState || state !== storedState) {
    console.error('Invalid callback parameters');
    return NextResponse.redirect(await constructFullUrl(req, "/api/auth/login"));
  }

  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);
    const userInfo = await auth0Client.getUserInfo(tokens.access_token);

    const response = NextResponse.redirect(await constructFullUrl(req, "/"));

    const secureCookie = env.DISABLE_SECURE_COOKIES !== 'true';
    response.cookies.set("access_token", tokens.access_token, {
      httpOnly: true,
      secure: secureCookie,
    });
    if (tokens.refresh_token) {
      response.cookies.set("refresh_token", tokens.refresh_token, {
        httpOnly: true,
        secure: secureCookie,
      });
    }
    response.cookies.delete("auth_state");

    // Store full user info in a cookie
    response.cookies.set('user_info', JSON.stringify(userInfo), { 
      httpOnly: true, 
      secure: secureCookie,
      maxAge: 7 * 24 * 60 * 60 // 7 days
    });

    return response;
  } catch (error) {
    console.error("Error during callback:", error);
    return NextResponse.redirect(await constructFullUrl(req, "/auth/error"));
  }
}

export async function handleLogout(req: NextRequest): Promise<NextResponse> {
  const cloudflareContext = await getCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: await constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE,
  });

  // Construct the return URL (where to redirect after Auth0 logout)
  const returnTo = await constructFullUrl(req, "/");

  // Get the Auth0 logout URL
  const logoutUrl = auth0Client.getLogoutUrl(returnTo);

  // Create a response that will redirect to the Auth0 logout URL
  const response = NextResponse.redirect(logoutUrl);

  // Clear the cookies
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  response.cookies.delete("user_info");

  return response;
}

