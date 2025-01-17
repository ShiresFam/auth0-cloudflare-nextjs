import { NextRequest, NextResponse } from "next/server";
import { CloudflareContext } from "@opennextjs/cloudflare";
export declare function handleAuth(): (req: NextRequest, context: CloudflareContext) => Promise<NextResponse<unknown>>;
