import { NextRequest } from "next/server";

export function createProperRequest(originalRequest: NextRequest): NextRequest {
  // Try referer first as it contains the full origin
  const referer = originalRequest.headers.get("referer");
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const originalUrl = new URL(originalRequest.url);

      // Use referer's origin with original path and search
      const properUrl = new URL(
        originalUrl.pathname + originalUrl.search,
        refererUrl.origin
      );


      return new NextRequest(properUrl, {
        method: originalRequest.method,
        headers: originalRequest.headers,
        body: originalRequest.body,
        credentials: originalRequest.credentials,
      });
    } catch (e) {
      console.warn("Failed to parse referer URL:", e);
    }
  }

  // Fall back to x-forwarded headers if referer isn't available
  const forwardedHost = originalRequest.headers.get("x-forwarded-host");
  const forwardedProto = originalRequest.headers.get("x-forwarded-proto");

  if (forwardedHost && forwardedProto) {
    const originalUrl = new URL(originalRequest.url);
    const properUrl = new URL(
      originalUrl.pathname + originalUrl.search,
      `${forwardedProto}://${forwardedHost}`
    );

    return new NextRequest(properUrl, {
      method: originalRequest.method,
      headers: originalRequest.headers,
      body: originalRequest.body,
      credentials: originalRequest.credentials,
    });
  }

  console.warn("No proper headers found to create URL, using original request");
  return originalRequest;
}
