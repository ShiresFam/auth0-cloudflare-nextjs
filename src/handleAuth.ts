import { NextRequest, NextResponse } from "next/server";
import { handleLogin, handleCallback, handleLogout } from "./authUtils";
import { getSession } from "./getSession";

export function handleAuth() {
  return async (req: NextRequest) => {
    const { pathname } = new URL(req.url);
    console.log("pathname", pathname);
    console.log("req.url", req.nextUrl);
    console.log("headers", req.headers);

    switch (pathname) {
      case "/api/auth/login":
        return handleLogin(req);
      case "/api/auth/callback":
        return handleCallback(req);
      case "/api/auth/logout":
        return handleLogout(req);
      case "/api/auth/me":
        const session = await getSession(req);
        if (session?.user) {
          return NextResponse.json(session.user);
        }
        return new NextResponse("Unauthorized", { status: 401 });
      default:
        return new NextResponse("Not Found", { status: 404 });
    }
  };
}
