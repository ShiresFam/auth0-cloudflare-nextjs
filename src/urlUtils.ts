import { NextRequest } from 'next/server';
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { createAuth0CloudflareContext } from "./contextUtils";

export async function constructBaseUrl(req: NextRequest): Promise<string> {
  const cloudflareContext = await getCloudflareContext();
  const context = createAuth0CloudflareContext(cloudflareContext);
  const { env } = context;

  if (env.AUTH0_BASE_URL) {
    return env.AUTH0_BASE_URL;
  }

  let protocol = req.headers.get('x-forwarded-proto') || 'http';
  const host = req.headers.get('x-forwarded-host') || req.headers.get('host') || 'localhost:8000';

  // Ensure HTTPS for non-localhost
  if (!host.includes('localhost') && !host.includes('127.0.0.1')) {
    protocol = 'https';
  }

  const baseUrl = `${protocol}://${host}`;
  return baseUrl;
}

export async function constructFullUrl(req: NextRequest, path: string): Promise<string> {
  const baseUrl = await constructBaseUrl(req);
  const fullUrl = new URL(path, baseUrl).toString();

  return fullUrl;
}

