import { NextRequest, NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { handleLogin, handleCallback, handleLogout } from "./authUtils";
import { getSession } from "./getSession";
import { createProperRequest } from "./utils/request";
import { Auth0CloudflareContext } from "./types";

export function handleAuth() {
  // Return a function that matches Next.js route handler signature
  return async (req: NextRequest) => {
    try {
      // Get context and create proper request inside the handler
      const context = (await getCloudflareContext()) as Auth0CloudflareContext;
      const properRequest = createProperRequest(req);

      console.log("Auth handler processing:", {
        originalUrl: req.url,
        properUrl: properRequest.url,
        pathname: new URL(properRequest.url).pathname,
      });

      // Pass the proper request to the actual handler
      return await handleAuthRequest(properRequest, context);
    } catch (error) {
      console.error("Auth handler error:", error);
      return new NextResponse("Internal Server Error", { status: 500 });
    }
  };
}

// Move the main logic to a separate function
async function handleAuthRequest(
  req: NextRequest,
  context: Auth0CloudflareContext
) {
  const url = new URL(req.url);
  const { pathname } = url;

  switch (pathname) {
    case "/api/auth/login":
      return handleLogin(req, context);
    case "/api/auth/callback":
      return handleCallback(req, context);
    case "/api/auth/logout":
      return handleLogout(req);
    // case "/api/auth/me":
    //   const session = await getSession(req, context);
    //   if (session?.user) {
    //     return NextResponse.json(session.user);
    //   }
    //   return new NextResponse("Unauthorized", { status: 401 });
    default:
      return new NextResponse("Not Found", { status: 404 });
  }
}
