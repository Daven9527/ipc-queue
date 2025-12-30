import { NextResponse } from "next/server";
import { verifyUser } from "./users";
import type { UserRole } from "./users";

export async function authenticateBasic(request: Request) {
  const header = request.headers.get("authorization");
  if (!header || !header.startsWith("Basic ")) {
    return null;
  }

  const encoded = header.slice("Basic ".length).trim();
  let decoded: string;
  try {
    decoded = Buffer.from(encoded, "base64").toString("utf-8");
  } catch (error) {
    console.error("Failed to decode auth header", error);
    return null;
  }

  const [username, ...rest] = decoded.split(":");
  const password = rest.join(":");
  if (!username || password === undefined) {
    return null;
  }

  const user = await verifyUser(username, password);
  return user;
}

export async function requireRole(request: Request, role: UserRole) {
  const user = await authenticateBasic(request);
  if (!user || user.role !== role) {
    return NextResponse.json({ error: "未授權" }, { status: 401 });
  }
  return null;
}
