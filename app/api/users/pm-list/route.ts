import { NextResponse } from "next/server";
import { ensureDefaultUsers, listUsers } from "@/lib/users";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  // This endpoint is accessible without authentication for PM platform
  // It only returns PM and super users (excluding superadmin)
  await ensureDefaultUsers();
  const users = await listUsers();
  const filteredUsers = users.filter(
    (u) => u.username !== "superadmin" && (u.role === "pm" || u.role === "super")
  );
  return NextResponse.json({ users: filteredUsers });
}
