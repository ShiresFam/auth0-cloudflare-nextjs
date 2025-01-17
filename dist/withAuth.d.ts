import { NextRequest } from "next/server";
import { AuthenticatedHandler, Auth0CloudflareContext } from "./types";
export declare function withAuth(handler: AuthenticatedHandler): (req: NextRequest, context: Auth0CloudflareContext) => Promise<Response>;
