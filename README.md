# auth0-cloudflare-nextjs

A lightweight, type-safe authentication library for Next.js applications deployed on Cloudflare Workers, using Auth0 as the authentication provider.

## Features

- Easy integration with Next.js and Cloudflare Workers
- Type-safe authentication middleware
- Built-in handlers for login, logout, and callback
- Server-side session management
- Client-side React hooks and components
- Automatic token refresh
- Secure cookie handling
- Customizable authentication flow

## Installation

```bash
npm install auth0-cloudflare-nextjs
```

## Prerequisites

- An Auth0 account and application
- A Next.js project set up for deployment on Cloudflare Workers
- Node.js 14 or later

## Configuration

### Environment Variables

Add the following to your `wrangler.toml`:

```toml
[vars]
AUTH0_DOMAIN = "your-auth0-domain"
AUTH0_CLIENT_ID = "your-client-id"
AUTH0_CLIENT_SECRET = "your-client-secret"
AUTH0_CALLBACK_URL = "https://your-worker-domain.workers.dev/api/auth/callback"
AUTH0_AUDIENCE = "your-api-audience" # optional
AUTH0_BASE_URL = "https://your-base-url" # optional
DISABLE_SECURE_COOKIES = "false" # optional, defaults to false
```

### API Route Setup

Create a catch-all API route for Auth0:

```typescript
// app/api/auth/[auth0]/route.ts
import { handleAuth } from "auth0-cloudflare-nextjs";

export const GET = handleAuth();
```

### Middleware Protection

Create a middleware to protect routes:

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { withAuth } from "auth0-cloudflare-nextjs";
import { getCloudflareContext } from "@opennextjs/cloudflare";

export async function middleware(request: NextRequest) {
  const context = await getCloudflareContext();

  const handler = withAuth(async (req, ctx) => {
    return NextResponse.next();
  });

  return handler(request, context);
}

export const config = {
  matcher: ["/protected/:path*"],
};
```

## Usage

### Session Management

Access user sessions in server components:

```typescript
// Server Component
import { getServerSession } from "auth0-cloudflare-nextjs";

export default async function Page() {
  const session = await getServerSession();

  if (!session) {
    return <div>Not authenticated</div>;
  }

  return <div>Welcome {session.user.name}</div>;
}
```

For custom handlers:

```typescript
import { getSessionFromRequest } from "auth0-cloudflare-nextjs";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }
  return Response.json(session.user);
}
```

### Client-Side Authentication

Set up the provider in your root layout:

```typescript
// app/layout.tsx
import { UserProvider } from "auth0-cloudflare-nextjs/client";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html>
      <body>
        <UserProvider>{children}</UserProvider>
      </body>
    </html>
  );
}
```

Use the authentication hook in client components:

```typescript
"use client";
import { useUser } from "auth0-cloudflare-nextjs/client";

export default function Profile() {
  const { user, error, isLoading, login, logout } = useUser();

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>{error.message}</div>;
  if (!user) return <button onClick={login}>Login</button>;

  return (
    <div>
      <h2>{user.name}</h2>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### Custom Authentication Handlers

Customize the authentication flow:

```typescript
import { setAuthUtilOptions } from 'auth0-cloudflare-nextjs';

setAuthUtilOptions({
  onLogin: async (req, context, auth0Client) => {
    // Custom login logic
    return NextResponse.redirect('...');
  },
  onCallback: async (req, context, auth0Client) => {
    // Custom callback handling
    return NextResponse.redirect('...');
  },
  onLogout: async (req, context, auth0Client) => {
    // Custom logout logic
    return NextResponse.redirect('...');
  },
  onGetUser: async (req, context, auth0Client) => {
    // Custom user info retrieval
    return NextResponse.json({...});
  }
});
```

## Security Features

- **Secure Cookie Storage**: Tokens are stored in HttpOnly, secure cookies
- **Automatic Token Refresh**: Handles token expiration automatically
- **CSRF Protection**: Implements state parameter validation
- **Token Validation**: Verifies token signature, issuer, and audience
- **Configurable Security**: Adjustable secure cookie settings

## Error Handling

The library handles various authentication scenarios:

### Token Validation

- Expired tokens (with automatic refresh)
- Invalid signatures
- Incorrect issuers
- Invalid audiences

### Session Management

- Missing or invalid cookies
- Invalid callback state
- Failed token refresh attempts

### Network Issues

- Auth0 API connectivity problems
- Callback URL mismatches

## TypeScript Support

The library is written in TypeScript and provides full type definitions:

```typescript
import type {
  Auth0User,
  Auth0Config,
  AuthenticatedNextRequest,
  JWTPayload,
} from "auth0-cloudflare-nextjs";
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License.

## Support

If you encounter any issues or have questions:

1. Check the [GitHub Issues](https://github.com/yourusername/auth0-cloudflare-nextjs/issues)
2. Create a new issue if none exists
3. Join our community discussions

## Acknowledgements

- [Auth0](https://auth0.com) for their authentication platform
- [Next.js](https://nextjs.org) for the React framework
- [Cloudflare Workers](https://workers.cloudflare.com) for the serverless platform
