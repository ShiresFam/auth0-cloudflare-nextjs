import { NextRequest } from "next/server";
import { CloudflareContext } from "@opennextjs/cloudflare";
export declare function getSession(req: NextRequest, context: CloudflareContext): Promise<{
    user: import("jose").JWTPayload & import("./auth0Client").JWTPayload;
    accessToken: string;
} | null>;
