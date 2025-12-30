import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { getRecentLogs } from "@/lib/logs";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const authError = await requireRole(request, "super");
  if (authError) return authError;

  const logs = await getRecentLogs(2000);

  const header = ["ts", "username", "role", "action", "detail"];
  const lines = [header.join(",")];
  for (const log of logs) {
    const row = [
      log.ts.replace(/,/g, " "),
      (log.username || "").replace(/,/g, " "),
      (log.role || "").replace(/,/g, " "),
      (log.action || "").replace(/,/g, " "),
      (log.detail || "").replace(/,/g, " "),
    ];
    lines.push(row.join(","));
  }
  const csv = lines.join("\n");

  return new NextResponse(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="logs.csv"`,
    },
  });
}
