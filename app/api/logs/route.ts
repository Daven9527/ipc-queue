import { NextResponse } from "next/server";
import { authenticateBasic, requireRole } from "@/lib/auth";
import { addLog, getRecentLogs } from "@/lib/logs";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const authError = await requireRole(request, "super");
  if (authError) return authError;

  const url = new URL(request.url);
  const limit = Number(url.searchParams.get("limit") ?? "500");
  const raw = await redis.zrange("logs:z", 0, (Number.isFinite(limit) ? Math.max(1, Math.min(limit, 1000)) : 500) - 1, { rev: true }).catch(() => []);
  const logs = await getRecentLogs(Number.isFinite(limit) ? Math.max(1, Math.min(limit, 1000)) : 500);
  const count = await redis.zcard("logs:z").catch(() => 0);
  return NextResponse.json({ logs, count, raw });
}

export async function POST(request: Request) {
  // 嘗試從 Basic Auth 取得使用者，否則看 body
  const basicUser = await authenticateBasic(request);
  let body: any = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const username = basicUser?.username ?? body?.username;
  const role = basicUser?.role ?? body?.role ?? "unknown";
  const action = body?.action;
  const detail = body?.detail;

  if (!username || !action) {
    return NextResponse.json({ error: "缺少 username 或 action" }, { status: 400 });
  }

  await addLog({
    ts: new Date().toISOString(),
    username,
    role: String(role),
    action: String(action),
    detail: detail ? String(detail) : undefined,
  });

  return NextResponse.json({ ok: true });
}
