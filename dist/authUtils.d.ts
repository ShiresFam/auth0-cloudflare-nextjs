import { NextRequest, NextResponse } from "next/server";
import { CloudflareContext } from "@opennextjs/cloudflare";
export declare function handleLogin(req: NextRequest, context: CloudflareContext): Promise<NextResponse>;
export declare function handleCallback(req: NextRequest, context: CloudflareContext): Promise<NextResponse>;
export declare function handleLogout(req: NextRequest): Promise<NextResponse>;
