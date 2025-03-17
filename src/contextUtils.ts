import { CloudflareContext, getCloudflareContext } from "@opennextjs/cloudflare";
import { Auth0CloudflareContext, Auth0Env } from "./types";

export function createAuth0CloudflareContext(
  baseContext: CloudflareContext
): Auth0CloudflareContext {
  const requiredEnvVars = [
    "AUTH0_DOMAIN",
    "AUTH0_CLIENT_ID",
    "AUTH0_CLIENT_SECRET",
    "AUTH0_CALLBACK_URL",
  ];
  const missingEnvVars = requiredEnvVars.filter(
    (varName) => !(varName in baseContext.env)
  );

  if (missingEnvVars.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingEnvVars.join(", ")}`
    );
  }

  const auth0Env: Auth0Env = {
    AUTH0_DOMAIN: (baseContext.env as Auth0Env).AUTH0_DOMAIN,
    AUTH0_CLIENT_ID: (baseContext.env as Auth0Env).AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET: (baseContext.env as Auth0Env).AUTH0_CLIENT_SECRET,
    AUTH0_CALLBACK_URL: (baseContext.env as Auth0Env).AUTH0_CALLBACK_URL,
    AUTH0_AUDIENCE: (baseContext.env as Auth0Env).AUTH0_AUDIENCE,
  };

  return {
    ...baseContext,
    env: {
      ...baseContext.env,
      ...auth0Env,
    },
  };
}

export async function getCompatibleCloudflareContext(): Promise<CloudflareContext> {
  try {
    // Try the new version with async flag
    return await getCloudflareContext({ async: true });
  } catch (error) {
    try {
      // Fall back to old version without options
      return await getCloudflareContext();
    } catch (fallbackError) {
      console.error('Failed to get Cloudflare context:', fallbackError);
      throw fallbackError;
    }
  }
}