export function createAuth0CloudflareContext(baseContext) {
    const requiredEnvVars = [
        "AUTH0_DOMAIN",
        "AUTH0_CLIENT_ID",
        "AUTH0_CLIENT_SECRET",
        "AUTH0_CALLBACK_URL",
    ];
    const missingEnvVars = requiredEnvVars.filter((varName) => !(varName in baseContext.env));
    if (missingEnvVars.length > 0) {
        throw new Error(`Missing required environment variables: ${missingEnvVars.join(", ")}`);
    }
    const auth0Env = {
        AUTH0_DOMAIN: baseContext.env.AUTH0_DOMAIN,
        AUTH0_CLIENT_ID: baseContext.env.AUTH0_CLIENT_ID,
        AUTH0_CLIENT_SECRET: baseContext.env.AUTH0_CLIENT_SECRET,
        AUTH0_CALLBACK_URL: baseContext.env.AUTH0_CALLBACK_URL,
        AUTH0_AUDIENCE: baseContext.env.AUTH0_AUDIENCE,
    };
    return {
        ...baseContext,
        env: {
            ...baseContext.env,
            ...auth0Env,
        },
    };
}
