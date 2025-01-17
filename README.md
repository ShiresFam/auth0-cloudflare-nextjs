# Auth0 Cloudflare Next.js Authentication Library

A lightweight, type-safe authentication library for Next.js applications deployed on Cloudflare Workers, using Auth0 as the authentication provider.

## Features

- Easy integration with Next.js and Cloudflare Workers
- Type-safe authentication middleware
- Built-in handlers for login, logout, and callback
- Customizable Auth0 client
- Token refresh functionality
- Compatible with Next.js 14.2.5 and above

## Installation

Install the package using npm:

```bash
npm install auth0-cloudflare-nextjs
```

## Prerequisites

- An Auth0 account and application
- A Next.js project set up for deployment on Cloudflare Workers
- Node.js 14 or later

## Configuration

1. Set up your Auth0 application and note down the following:
   - Domain
   - Client ID
   - Client Secret

2. Add the following environment variables to your `wrangler.toml` file:

```toml
[vars]
AUTH0_DOMAIN = "your-auth0-domain"
AUTH0_CLIENT_ID = "your-client-id"
AUTH0_CLIENT_SECRET = "your-client-secret"
AUTH0_CALLBACK_URL = "https://your-worker-domain.workers.dev/api/callback"
AUTH0_AUDIENCE = "your-api-audience" # optional
```

## Usage

### Basic Setup

1. Create login, callback, and logout API routes:

```typescript
// app/api/login/route.ts
import { handleLogin, CloudflareEnv } from 'auth0-cloudflare-nextjs';
import { NextRequest } from 'next/server';

export function GET(req: NextRequest, context: { env: CloudflareEnv }) {
  return handleLogin(req, context.env);
}

// app/api/callback/route.ts
import { handleCallback, CloudflareEnv } from 'auth0-cloudflare-nextjs';
import { NextRequest } from 'next/server';

export function GET(req: NextRequest, context: { env: CloudflareEnv }) {
  return handleCallback(req, context.env);
}

// app/api/logout/route.ts
import { handleLogout } from 'auth0-cloudflare-nextjs';
import { NextRequest } from 'next/server';

export function GET(req: NextRequest) {
  return handleLogout(req);
}
```

2. Protect your API routes using the `withAuth` middleware:

```typescript
// app/api/protected/route.ts
import { withAuth, AuthenticatedRequest, CloudflareEnv } from 'auth0-cloudflare-nextjs';
import { NextResponse } from 'next/server';

async function handler(req: AuthenticatedRequest, env: CloudflareEnv) {
  const userEmail = req.auth.payload.email;
  return NextResponse.json({ message: `Hello, ${userEmail}!` });
}

export const GET = withAuth(handler);
```

### Advanced Usage

#### Customizing the Auth0 Client

You can extend the `Auth0Client` class to add custom functionality:

```typescript
import { Auth0Client, Auth0Config, TokenResponse } from 'auth0-cloudflare-nextjs';

class CustomAuth0Client extends Auth0Client {
  constructor(config: Auth0Config) {
    super(config);
  }

  async exchangeCodeForTokens(code: string): Promise<TokenResponse> {
    const tokens = await super.exchangeCodeForTokens(code);
    // Add custom logic here
    return tokens;
  }

  // Add new methods as needed
}
```

#### Using Custom Claims

If your JWT includes custom claims, you can extend the `JWTPayload` interface:

```typescript
import { JWTPayload } from 'auth0-cloudflare-nextjs';

interface CustomJWTPayload extends JWTPayload {
  custom_claim?: string;
}

// Use this interface when working with the verified token
const verifiedToken = await auth0Client.verifyToken<CustomJWTPayload>(token);
console.log(verifiedToken.payload.custom_claim);
```

## API Reference

### `Auth0Client`

The main class for interacting with Auth0. It provides methods for:

- `getAuthorizationUrl(state: string): Promise<string>`
- `exchangeCodeForTokens(code: string): Promise<TokenResponse>`
- `verifyToken(token: string): Promise<jose.JWTVerifyResult<JWTPayload>>`
- `refreshToken(refreshToken: string): Promise<TokenResponse>`

### `withAuth`

A middleware function to protect API routes. It verifies the access token and refreshes it if necessary.

### Utility Functions

- `handleLogin`: Initiates the login process
- `handleCallback`: Handles the Auth0 callback after successful authentication
- `handleLogout`: Logs out the user

### Types

- `Auth0Config`: Configuration interface for Auth0Client
- `TokenResponse`: Interface for the token response from Auth0
- `JWTPayload`: Interface for the JWT payload (extendable for custom claims)
- `CloudflareEnv`: Type for Cloudflare environment variables
- `AuthenticatedRequest`: Extended NextRequest with auth property
- `AuthenticatedHandler`: Type for request handlers protected by withAuth

## Error Handling

The library throws errors in various scenarios:

- Token exchange failure
- Token verification failure
- Token refresh failure

It's recommended to wrap your API calls in try-catch blocks and handle these errors appropriately in your application.

## Security Considerations

- Always use HTTPS in production
- Store tokens securely (this library uses HttpOnly, secure cookies)
- Implement proper CSRF protection in your application
- Regularly rotate your Auth0 client secret

## Cloudflare Workers Compatibility

This library is designed to work with Cloudflare Workers, which means:

- It doesn't rely on Node.js-specific features
- It uses the Web Crypto API for cryptographic operations
- Environment variables are accessed through the Cloudflare Workers runtime

## Troubleshooting

Common issues and their solutions:

1. "Token verification failed": Ensure your Auth0 domain and audience are correctly set.
2. "Failed to exchange code for tokens": Check your Auth0 client ID and secret.
3. "Callback URL mismatch": Verify that the callback URL in your Auth0 settings matches the one in your application.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure your code adheres to the existing style and passes all tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.

## Acknowledgements

- [Auth0](https://auth0.com/) for their authentication platform
- [Next.js](https://nextjs.org/) for the React framework
- [Cloudflare Workers](https://workers.cloudflare.com/) for the serverless platform
