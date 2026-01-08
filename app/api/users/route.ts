import { NextResponse } from "next/server";
import { authenticateBasic, requireRole } from "@/lib/auth";
import { addLog } from "@/lib/logs";
import { createOrUpdateUser, ensureDefaultUsers, listUsers } from "@/lib/users";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  // Allow both pm and super roles to access
  const authError = await requireRole(request, "pm");
  if (authError) {
    const superError = await requireRole(request, "super");
    if (superError) return superError;
  }

  await ensureDefaultUsers();
  const users = await listUsers();
  // Filter out superadmin and only return pm and super roles
  const filteredUsers = users.filter(
    (u) => u.username !== "superadmin" && (u.role === "pm" || u.role === "super")
  );
  return NextResponse.json({ users: filteredUsers });
}

export async function POST(request: Request) {
  const authError = await requireRole(request, "super");
  if (authError) return authError;

  try {
    const actor = await authenticateBasic(request);
    const body = await request.json();
    const { username, password, role } = body || {};

    if (!username || !password || (role !== "pm" && role !== "super")) {
      return NextResponse.json(
        { error: "請提供帳號、密碼與角色 (pm/super)" },
        { status: 400 }
      );
    }

    await ensureDefaultUsers();
    const saved = await createOrUpdateUser({
      username: String(username),
      password: String(password),
      role,
    });

    await addLog({
      ts: new Date().toISOString(),
      username: actor?.username || "unknown",
      role: actor?.role || "super",
      action: "user:create",
      detail: `create ${username} (${role})`,
    });

    return NextResponse.json({ ok: true, user: saved });
  } catch (error) {
    console.error("Failed to create user:", error);
    return NextResponse.json({ error: "建立使用者失敗" }, { status: 500 });
  }
}
