import { NextResponse } from "next/server";
import { handleLogin, handleCallback, handleLogout } from "./authUtils";
import { getSession } from "./getSession";
export function handleAuth() {
    return async (req, context) => {
        const { pathname } = new URL(req.url);
        switch (pathname) {
            case "/api/auth/login":
                return handleLogin(req, context);
            case "/api/auth/callback":
                return handleCallback(req, context);
            case "/api/auth/logout":
                return handleLogout(req);
            case "/api/auth/me":
                const session = await getSession(req, context);
                if (session?.user) {
                    return NextResponse.json(session.user);
                }
                return new NextResponse("Unauthorized", { status: 401 });
            default:
                return new NextResponse("Not Found", { status: 404 });
        }
    };
}
