import { NextResponse } from "next/server";
import { ensureDefaultUsers, verifyUser } from "@/lib/users";
import { addLog } from "@/lib/logs";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { username, password } = body || {};

    if (!username || !password) {
      return NextResponse.json(
        { error: "請提供帳號與密碼" },
        { status: 400 }
      );
    }

    await ensureDefaultUsers();
    const user = await verifyUser(String(username), String(password));
    if (!user) {
      return NextResponse.json({ error: "帳號或密碼錯誤" }, { status: 401 });
    }

    await addLog({
      ts: new Date().toISOString(),
      username: user.username,
      role: user.role,
      action: "login",
    });

    return NextResponse.json({ ok: true, username: user.username, role: user.role });
  } catch (error) {
    console.error("Login failed:", error);
    return NextResponse.json({ error: "登入失敗" }, { status: 500 });
  }
}
