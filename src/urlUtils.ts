import { NextRequest } from "next/server";

export function constructBaseUrl(req: NextRequest): string {
  let baseUrl: string | undefined;

  // Try to use the referer first
  const referer = req.headers.get("referer");
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      baseUrl = `${refererUrl.protocol}//${refererUrl.host}`;
    } catch (error) {
      console.error("Error parsing referer:", error);
    }
  }

  // Initialize baseUrl as undefined

  // If referer is not available or invalid, fall back to other headers
  if (!baseUrl) {
    const protocol = req.headers.get("x-forwarded-proto") || "https";
    const host =
      req.headers.get("x-forwarded-host") ||
      req.headers.get("host") ||
      "localhost";
    baseUrl = `${protocol}://${host}`;
  }

  console.log("Constructed Base URL:", baseUrl);
  return baseUrl;
}

export function constructFullUrl(req: NextRequest, path: string): string {
  const baseUrl = constructBaseUrl(req);
  const fullUrl = new URL(path, baseUrl).toString();

  console.log("Constructed Full URL:", fullUrl);
  return fullUrl;
}
