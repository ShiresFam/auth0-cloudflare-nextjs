import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const response = NextResponse.redirect(new URL('/', req.url));

  response.cookies.delete('access_token');
  response.cookies.delete('refresh_token');

  return response;
}

