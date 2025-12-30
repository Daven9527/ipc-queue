import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { createOrUpdateUser, ensureDefaultUsers, getUser } from "@/lib/users";
import { redis } from "@/lib/redis";
import { addLog } from "@/lib/logs";
import { authenticateBasic } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function PATCH(request: Request, context: { params: Promise<{ username: string }> }) {
  const authError = await requireRole(request, "super");
  if (authError) return authError;

  const { username } = await context.params;
  if (!username) {
    return NextResponse.json({ error: "缺少使用者帳號" }, { status: 400 });
  }

  try {
    const actor = await authenticateBasic(request);
    await ensureDefaultUsers();
    const existing = await getUser(username);
    if (!existing) {
      return NextResponse.json({ error: "找不到該使用者" }, { status: 404 });
    }

    const body = await request.json();
    const newPassword = body?.password as string | undefined;
    const newRole = body?.role as string | undefined;

    if (username === "superadmin" && newPassword !== undefined) {
      return NextResponse.json({ error: "superadmin 密碼不可變更" }, { status: 400 });
    }

    const role = newRole === "pm" || newRole === "super" ? newRole : existing.role;
    const password = newPassword ? String(newPassword) : existing.password;

    const saved = await createOrUpdateUser({
      username,
      password,
      role,
    });

    await addLog({
      ts: new Date().toISOString(),
      username: actor?.username || "unknown",
      role: actor?.role || "super",
      action: "user:update",
      detail: `update ${username} (${role})`,
    });

    return NextResponse.json({ ok: true, user: saved });
  } catch (error) {
    console.error("Failed to update user:", error);
    return NextResponse.json({ error: "更新使用者失敗" }, { status: 500 });
  }
}

export async function GET(request: Request, context: { params: Promise<{ username: string }> }) {
  const authError = await requireRole(request, "super");
  if (authError) return authError;

  const { username } = await context.params;
  if (!username) {
    return NextResponse.json({ error: "缺少使用者帳號" }, { status: 400 });
  }

  try {
    await ensureDefaultUsers();
    const user = await getUser(username);
    if (!user) {
      return NextResponse.json({ error: "找不到該使用者" }, { status: 404 });
    }
    // 只供除錯使用：回傳角色與密碼
    return NextResponse.json({ username: user.username, role: user.role, password: user.password });
  } catch (error) {
    console.error("Failed to fetch user:", error);
    return NextResponse.json({ error: "取得使用者失敗" }, { status: 500 });
  }
}

export async function DELETE(request: Request, context: { params: Promise<{ username: string }> }) {
  const authError = await requireRole(request, "super");
  if (authError) return authError;

  const { username } = await context.params;
  if (!username) {
    return NextResponse.json({ error: "缺少使用者帳號" }, { status: 400 });
  }

  try {
    const actor = await authenticateBasic(request);
    await ensureDefaultUsers();
    await redis.del(`user:${username}`);
    await redis.srem("users:list", username);

    await addLog({
      ts: new Date().toISOString(),
      username: actor?.username || "unknown",
      role: actor?.role || "super",
      action: "user:delete",
      detail: `delete ${username}`,
    });

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("Failed to delete user:", error);
    return NextResponse.json({ error: "刪除使用者失敗" }, { status: 500 });
  }
}
