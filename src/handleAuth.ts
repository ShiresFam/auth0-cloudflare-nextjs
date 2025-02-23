// src/handleAuth.ts
import { NextRequest, NextResponse } from "next/server";
import {
  handleLogin,
  handleCallback,
  handleLogout,
  handleGetUser,
} from "./authUtils";

export function handleAuth() {
  return async (req: NextRequest) => {
    const { pathname } = new URL(req.url);

    switch (pathname) {
      case "/api/auth/login":
        return handleLogin(req);
      case "/api/auth/callback":
        return handleCallback(req);
      case "/api/auth/logout":
        return handleLogout(req);
      case "/api/auth/me":
        return handleGetUser(req);
      default:
        return new NextResponse("Not Found", { status: 404 });
    }
  };
}
