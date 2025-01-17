import { Auth0Client } from "./auth0Client";
import { createAuth0CloudflareContext } from "./contextUtils";
export async function getSession(req, context) {
    const auth0Context = createAuth0CloudflareContext(context);
    const { env } = auth0Context;
    const auth0Client = new Auth0Client({
        domain: env.AUTH0_DOMAIN,
        clientId: env.AUTH0_CLIENT_ID,
        clientSecret: env.AUTH0_CLIENT_SECRET,
        callbackUrl: env.AUTH0_CALLBACK_URL,
        audience: env.AUTH0_AUDIENCE,
    });
    const accessToken = req.cookies.get("access_token")?.value;
    if (!accessToken) {
        return null;
    }
    try {
        const verifyResult = await auth0Client.verifyToken(accessToken);
        return {
            user: verifyResult.payload,
            accessToken,
        };
    }
    catch (error) {
        console.error("Error verifying token:", error);
        return null;
    }
}
