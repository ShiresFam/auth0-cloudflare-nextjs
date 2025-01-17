# auth0-cloudflare-nextjs

A lightweight, type-safe authentication library for Next.js applications deployed on Cloudflare Workers, using Auth0 as the authentication provider.

## Features

- Easy integration with Next.js and Cloudflare Workers
- Type-safe authentication middleware
- Built-in handlers for login, logout, and callback
- Customizable Auth0 client
- Token refresh functionality
- Server-side session handling
- Client-side React components for easy integration
- Catch-all API route for simplified setup
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
AUTH0_CALLBACK_URL = "https://your-worker-domain.workers.dev/api/auth/callback"
AUTH0_AUDIENCE = "your-api-audience" # optional
```

## Usage

### Setting up the catch-all API route

Create a catch-all API route for Auth0 in your Next.js project:

```typescript
// app/api/auth/[auth0]/route.ts
import { handleAuth } from 'auth0-cloudflare-nextjs';
import { getCloudflareContext } from '@opennextjs/cloudflare';

export const GET = async (req: NextRequest) => {
  const context = await getCloudflareContext();
  return handleAuth()(req, context);
};
```

### Setting up middleware

Create a `middleware.ts` file in the root of your Next.js project:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { withAuth } from 'auth0-cloudflare-nextjs';
import { getCloudflareContext } from '@opennextjs/cloudflare';

export async function middleware(request: NextRequest) {
  const context = await getCloudflareContext();
  
  const handler = withAuth(async (req, ctx) => {
    // This function will only be called if the user is authenticated
    // You can add additional logic here if needed
    return NextResponse.next();
  });

  return handler(request, context);
}

// Optionally, you can specify which routes should be protected
export const config = {
  matcher: ['/protected/:path*'],
};
```

### Server-side usage

You can use the `getSession` function in your server-side code:

```typescript
import { getSession } from 'auth0-cloudflare-nextjs';
import { getCloudflareContext } from '@opennextjs/cloudflare';
import { headers } from 'next/headers';

export default async function ProfileServer() {
  const req = { headers: headers() } as NextRequest;
  const context = await getCloudflareContext();
  const session = await getSession(req, context);

  if (!session?.user) {
    return <div>Not logged in</div>;
  }

  const { user } = session;

  return (
    <div>
      <img src={user.picture || "/placeholder.svg"} alt={user.name} />
      <h2>{user.name}</h2>
      <p>{user.email}</p>
    </div>
  );
}
```

### Client-side usage

Wrap your app with the `UserProvider`:

```typescript
// app/layout.tsx
import { UserProvider } from 'auth0-cloudflare-nextjs/client';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <UserProvider>
        <body>{children}</body>
      </UserProvider>
    </html>
  );
}
```

Use the `useUser` hook in your client components:

```typescript
'use client';

import { useUser } from 'auth0-cloudflare-nextjs/client';

export default function ProfileClient() {
  const { user, error, isLoading } = useUser();

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>{error.message}</div>;

  return (
    user && (
      <div>
        <img src={user.picture || "/placeholder.svg"} alt={user.name} />
        <h2>{user.name}</h2>
        <p>{user.email}</p>
      </div>
    )
  );
}
```

## API Reference

### `Auth0Client`

The main class for interacting with Auth0. It provides methods for:

- `getAuthorizationUrl(state: string): Promise<string>`
- `exchangeCodeForTokens(code: string): Promise<TokenResponse>`
- `verifyToken(token: string): Promise<jose.JWTVerifyResult & { payload: JWTPayload }>`
- `refreshToken(refreshToken: string): Promise<TokenResponse>`

### `withAuth`

A middleware function to protect API routes. It verifies the access token and refreshes it if necessary.

### `handleAuth`

A function that creates a catch-all handler for Auth0-related routes.

### `getSession`

A function to retrieve the current user's session on the server-side.

### `UserProvider`

A React component that provides Auth0 user context to your application.

### `useUser`

A React hook that provides access to the current user's information in client components.

## Types

- `Auth0Config`: Configuration interface for Auth0Client
- `TokenResponse`: Interface for the token response from Auth0
- `JWTPayload`: Interface for the JWT payload (extendable for custom claims)
- `Auth0CloudflareContext`: Extended Cloudflare context with Auth0-specific environment variables
- `AuthenticatedNextRequest`: Extended NextRequest with auth property
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

## License

This project is licensed under the MIT License.

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.

## Acknowledgements

- [Auth0](https://auth0.com/) for their authentication platform
- [Next.js](https://nextjs.org/) for the React framework
- [Cloudflare Workers](https://workers.cloudflare.com/) for the serverless platform
