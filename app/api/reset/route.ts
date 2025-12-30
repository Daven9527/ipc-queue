import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";
import { authenticateBasic, requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const authError = await requireRole(request, "super");
  if (authError) return authError;

  // 僅允許 superadmin 執行重置
  const user = await authenticateBasic(request);
  if (!user || user.username !== "superadmin") {
    return NextResponse.json({ error: "僅 superadmin 可重置" }, { status: 403 });
  }

  try {
    // Get all ticket numbers before clearing
    const ticketNumbers = await redis.lrange<number[]>("queue:tickets", 0, -1);
    
    // Delete all ticket info hashes
    if (ticketNumbers && ticketNumbers.length > 0) {
      const keys = ticketNumbers.map((num) => `queue:ticket:${num}`);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    }

    await redis.mset({
      "queue:current": 0,
      "queue:last": 0,
      "queue:next": 1,
    });
    // Clear the tickets list
    await redis.del("queue:tickets");

    return NextResponse.json({ ok: true });
  } catch (error) {
    return NextResponse.json(
      { error: "重置失敗" },
      { status: 500 }
    );
  }
}
