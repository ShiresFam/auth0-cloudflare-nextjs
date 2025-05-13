import { NextRequest, NextResponse } from "next/server";
import { Auth0Client } from "./auth0Client";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { createAuth0CloudflareContext } from "./contextUtils";
import { constructFullUrl } from "./urlUtils";
import { getSessionFromRequest } from "./getSession";

export type AuthUtilCallback = (
  req: NextRequest,
  context: ReturnType<typeof createAuth0CloudflareContext>,
  auth0Client: Auth0Client
) => Promise<NextResponse>;

export interface AuthUtilOptions {
  onLogin?: AuthUtilCallback;
  onCallback?: AuthUtilCallback;
  onLogout?: AuthUtilCallback;
  onGetUser?: AuthUtilCallback;
  configureResponse?: (response: NextResponse) => NextResponse;
}

let customOptions: AuthUtilOptions = {};

export function setAuthUtilOptions(options: AuthUtilOptions) {
  customOptions = options;
}

function configureAuthResponse(response: NextResponse): NextResponse {
  if (customOptions.configureResponse) {
    return customOptions.configureResponse(response);
  }
  return response;
}

export async function handleLogin(req: NextRequest): Promise<NextResponse> {
  const cloudflareContext = await getCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  const callbackUrl = await constructFullUrl(req, "/api/auth/callback");
  const { searchParams } = new URL(req.url);
  const returnTo = searchParams.get("returnTo");

  // Validate returnTo URL is from our domain
  if (returnTo && !returnTo.startsWith("/")) {
    try {
      const returnToUrl = new URL(returnTo);
      const appUrl = new URL(await constructFullUrl(req, "/"));
      if (returnToUrl.origin !== appUrl.origin) {
        console.error("Invalid returnTo URL: must be from same origin");
        return configureAuthResponse(
          NextResponse.redirect(await constructFullUrl(req, "/auth/error"))
        );
      }
    } catch (e) {
      console.error("Invalid returnTo URL:", e);
      return configureAuthResponse(
        NextResponse.redirect(await constructFullUrl(req, "/auth/error"))
      );
    }
  }

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: callbackUrl,
    audience: env.AUTH0_AUDIENCE,
  });

  if (customOptions.onLogin) {
    return configureAuthResponse(
      await customOptions.onLogin(req, context, auth0Client)
    );
  }

  try {
    const state = crypto.randomUUID();
    // Include returnTo in state parameter for better security
    const stateData = {
      state,
      returnTo: returnTo || "/"
    };
    const stateParam = Buffer.from(JSON.stringify(stateData)).toString("base64url");

    const authorizationUrl = await auth0Client.getAuthorizationUrl(stateParam);

    const response = NextResponse.redirect(authorizationUrl);
    const secureCookie = env.DISABLE_SECURE_COOKIES !== "true";
    response.cookies.set("auth_state", stateParam, {
      httpOnly: true,
      secure: secureCookie,
    });

    return configureAuthResponse(response);
  } catch (error) {
    console.error("Error in handleLogin:", error);
    return configureAuthResponse(
      NextResponse.redirect(await constructFullUrl(req, "/auth/error"))
    );
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

  if (customOptions.onCallback) {
    return configureAuthResponse(
      await customOptions.onCallback(req, context, auth0Client)
    );
  }

  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");

  const storedState = req.cookies.get("auth_state")?.value;

  if (error) {
    console.error("Auth0 error:", error, errorDescription);
    return configureAuthResponse(
      NextResponse.redirect(await constructFullUrl(req, "/auth/error"))
    );
  }

  if (!code || !state || !storedState || state !== storedState) {
    console.error("Invalid callback parameters");
    return configureAuthResponse(
      NextResponse.redirect(await constructFullUrl(req, "/api/auth/login"))
    );
  }

  try {
    const stateData = JSON.parse(Buffer.from(state, "base64url").toString());
    const storedState = req.cookies.get("auth_state")?.value;

    if (!code || !state || !storedState || state !== storedState) {
      console.error("Invalid callback parameters");
      return configureAuthResponse(
        NextResponse.redirect(await constructFullUrl(req, "/api/auth/login"))
      );
    }

    const tokens = await auth0Client.exchangeCodeForTokens(code);
    const userInfo = await auth0Client.getUserInfo(tokens.access_token);

    // Use returnTo from state data
    const returnTo = stateData.returnTo || "/";
    const response = NextResponse.redirect(await constructFullUrl(req, returnTo));

    const secureCookie = env.DISABLE_SECURE_COOKIES !== "true";
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
    response.cookies.delete("auth_return_to"); // Clean up the returnTo cookie

    response.cookies.set("user_info", JSON.stringify(userInfo), {
      httpOnly: true,
      secure: secureCookie,
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });

    return configureAuthResponse(response);
  } catch (error) {
    console.error("Error during callback:", error);
    return configureAuthResponse(
      NextResponse.redirect(await constructFullUrl(req, "/auth/error"))
    );
  }
}

export async function handleLogout(req: NextRequest): Promise<NextResponse> {
  const cloudflareContext = await getCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  const { searchParams } = new URL(req.url);
  let returnTo = searchParams.get("returnTo") || "/";

  // Validate returnTo URL is from our domain
  if (!returnTo.startsWith("/")) {
    try {
      const returnToUrl = new URL(returnTo);
      const appUrl = new URL(await constructFullUrl(req, "/"));
      if (returnToUrl.origin !== appUrl.origin) {
        console.error("Invalid returnTo URL: must be from same origin");
        returnTo = "/";
      }
    } catch (e) {
      console.error("Invalid returnTo URL:", e);
      returnTo = "/";
    }
  }

  const auth0Client = new Auth0Client({
    domain: env.AUTH0_DOMAIN,
    clientId: env.AUTH0_CLIENT_ID,
    clientSecret: env.AUTH0_CLIENT_SECRET,
    callbackUrl: await constructFullUrl(req, "/api/auth/callback"),
    audience: env.AUTH0_AUDIENCE,
  });

  if (customOptions.onLogout) {
    return configureAuthResponse(
      await customOptions.onLogout(req, context, auth0Client)
    );
  }

  // Ensure returnTo is a full URL for Auth0
  const fullReturnTo = await constructFullUrl(req, returnTo);
  const logoutUrl = auth0Client.getLogoutUrl(fullReturnTo);
  const response = NextResponse.redirect(logoutUrl);

  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  response.cookies.delete("user_info");
  response.cookies.delete("auth_return_to");

  return configureAuthResponse(response);
}

export async function handleGetUser(req: NextRequest): Promise<NextResponse> {
  if (customOptions.onGetUser) {
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

    return configureAuthResponse(
      await customOptions.onGetUser(req, context, auth0Client)
    );
  }

  const session = await getSessionFromRequest(req);

  if (!session) {
    return configureAuthResponse(
      NextResponse.json({
        isAuthenticated: false,
        user: null,
      })
    );
  }

  return configureAuthResponse(
    NextResponse.json({
      isAuthenticated: true,
      user: session.user,
    })
  );
}

export function handleAuth() {
  return async (req: NextRequest): Promise<NextResponse> => {
    const { pathname } = new URL(req.url);

    // Handle OPTIONS request
    if (req.method === "OPTIONS") {
      const response = new NextResponse(null, { status: 200 });
      return configureAuthResponse(response);
    }

    if (pathname.endsWith("/login")) {
      return handleLogin(req);
    }
    if (pathname.endsWith("/callback")) {
      return handleCallback(req);
    }
    if (pathname.endsWith("/logout")) {
      return handleLogout(req);
    }
    if (pathname.endsWith("/me")) {
      return handleGetUser(req);
    }

    return configureAuthResponse(
      NextResponse.json({ error: "Not found" }, { status: 404 })
    );
  };
}
