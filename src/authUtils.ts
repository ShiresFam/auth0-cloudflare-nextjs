import { NextRequest, NextResponse } from "next/server";
import { Auth0Client } from "./auth0Client";
import { CloudflareContext } from "@opennextjs/cloudflare";
import { createAuth0CloudflareContext } from "./contextUtils";

export async function handleLogin(
  req: NextRequest,
  context: CloudflareContext
): Promise<NextResponse> {
  const auth0Context = createAuth0CloudflareContext(context);
  const { env } = auth0Context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE,
  });
  console.log("req.url from login", req.url);

  const state = crypto.randomUUID();
  const authorizationUrl = await auth0Client.getAuthorizationUrl(state);
  console.log("authorization_url", authorizationUrl);

  const response = NextResponse.redirect(authorizationUrl);
  response.cookies.set("auth_state", state, { httpOnly: true, secure: true });

  return response;
}

export async function handleCallback(
  req: NextRequest,
  context: CloudflareContext
): Promise<NextResponse> {
  const auth0Context = createAuth0CloudflareContext(context);
  const { env } = auth0Context;
  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: env.AUTH0_CALLBACK_URL,
    audience: env.AUTH0_AUDIENCE,
  });

  const origin = new URL(env.AUTH0_CALLBACK_URL).origin;

  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");

  const storedState = req.cookies.get("auth_state")?.value;

  if (!code || !state || !storedState || state !== storedState) {
    return NextResponse.redirect(new URL("/api/login", req.url));
  }

  try {
    const tokens = await auth0Client.exchangeCodeForTokens(code);

    console.log("req.url for callback", req.url);

    const response = NextResponse.redirect(new URL("/", req.url));

    console.log("response.url for callback", new URL("/", req.url).toString());

    response.cookies.set("access_token", tokens.access_token, {
      httpOnly: true,
      secure: true,
    });
    if (tokens.refresh_token) {
      response.cookies.set("refresh_token", tokens.refresh_token, {
        httpOnly: true,
        secure: true,
      });
    }
    response.cookies.delete("auth_state");

    return response;
  } catch (error) {
    console.error("Error during callback:", error);
    return NextResponse.redirect(new URL("/api/login", req.url));
  }
}

export async function handleLogout(req: NextRequest): Promise<NextResponse> {
  const response = NextResponse.redirect(new URL("/", req.url));

  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");

  return response;
}
