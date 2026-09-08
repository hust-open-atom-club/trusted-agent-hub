import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

interface JwtPayload {
  sub: string;
  role: string;
  exp: number;
}

function parseJwt(token: string): JwtPayload | null {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

/** 角色层级数值：越小越高 */
const ROLE_LEVEL: Record<string, number> = {
  admin: 0,
  reviewer: 1,
  submitter: 2,
  user: 3,
};

const PROTECTED: { path: string; minRole: string }[] = [
  { path: '/account', minRole: 'user' },
  { path: '/submit', minRole: 'submitter' },
  { path: '/submissions', minRole: 'submitter' },
  { path: '/packages', minRole: 'submitter' },
  { path: '/review', minRole: 'reviewer' },
  { path: '/admin', minRole: 'admin' },
];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const returnPath = `${pathname}${request.nextUrl.search}`;

  const rule = PROTECTED.find((r) => pathname.startsWith(r.path));
  if (!rule) return NextResponse.next();

  const tokenCookie = request.cookies.get('tah_token');
  const authHeader = request.headers.get('authorization');
  let token: string | null = null;

  if (tokenCookie) {
    token = tokenCookie.value;
  } else if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  if (!token) {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('redirect', returnPath);
    return NextResponse.redirect(loginUrl);
  }

  const payload = parseJwt(token);
  if (!payload || !Number.isFinite(payload.exp)) {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('redirect', returnPath);
    return NextResponse.redirect(loginUrl);
  }

  // Let AuthProvider renew an expired access token with the HttpOnly refresh
  // cookie before the page decides whether the session is still valid.
  if (payload.exp * 1000 < Date.now()) return NextResponse.next();

  const userLevel = ROLE_LEVEL[payload.role] ?? 99;
  const requiredLevel = ROLE_LEVEL[rule.minRole] ?? 99;

  if (userLevel > requiredLevel) {
    // 权限不足 → 重定向到首页
    return NextResponse.redirect(new URL('/', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/account/:path*', '/submit/:path*', '/submissions/:path*', '/packages/:path*', '/review/:path*', '/admin/:path*'],
};
