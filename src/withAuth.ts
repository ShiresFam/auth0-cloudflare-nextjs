import { NextRequest, NextResponse } from "next/server";
import { Auth0Client } from "./auth0Client";
import {
  AuthenticatedNextRequest,
  AuthenticatedHandler,
  Auth0CloudflareContext,
} from "./types";
import { createAuth0CloudflareContext } from "./contextUtils";

export function withAuth(handler: AuthenticatedHandler) {
  return async (req: NextRequest, context: Auth0CloudflareContext) => {
    const { env } = context;
    console.log("env", env);

    const auth0Client = new Auth0Client({
      domain: env.AUTH0_DOMAIN,
      clientId: env.AUTH0_CLIENT_ID,
      clientSecret: env.AUTH0_CLIENT_SECRET,
      callbackUrl: env.AUTH0_CALLBACK_URL,
      audience: env.AUTH0_AUDIENCE,
    });

    const accessToken = req.cookies.get("access_token")?.value;

    if (!accessToken) {
      return NextResponse.redirect(new URL("/api/auth/login", req.url));
    }

    try {
      const verifyResult = await auth0Client.verifyToken(accessToken);
      const authenticatedReq = new NextRequest(req, {
        headers: req.headers,
      }) as AuthenticatedNextRequest;
      authenticatedReq.auth = {
        token: accessToken,
        payload: verifyResult.payload,
      };
      return handler(authenticatedReq, context);
    } catch (error) {
      const refreshToken = req.cookies.get("refresh_token")?.value;

      if (refreshToken) {
        try {
          const newTokens = await auth0Client.refreshToken(refreshToken);
          const verifyResult = await auth0Client.verifyToken(
            newTokens.access_token
          );
          const authenticatedReq = new NextRequest(req, {
            headers: req.headers,
          }) as AuthenticatedNextRequest;
          authenticatedReq.auth = {
            token: newTokens.access_token,
            payload: verifyResult.payload,
          };
          const response = await handler(authenticatedReq, context);

          const nextResponse = NextResponse.json(
            response instanceof Response ? await response.json() : response,
            {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers,
            }
          );

          nextResponse.cookies.set("access_token", newTokens.access_token, {
            httpOnly: true,
            secure: true,
          });
          if (newTokens.refresh_token) {
            nextResponse.cookies.set("refresh_token", newTokens.refresh_token, {
              httpOnly: true,
              secure: true,
            });
          }

          return nextResponse;
        } catch (refreshError) {
          return NextResponse.redirect(new URL("/api/auth/login", req.url));
        }
      } else {
        return NextResponse.redirect(new URL("/api/auth/login", req.url));
      }
    }
  };
}
