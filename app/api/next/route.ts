import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const { pm } = body;

  // Determine the key prefix based on PM
  const currentKey = pm === "unassigned" ? "queue:current:unassigned" : pm ? `queue:current:${pm}` : "queue:current";
  const nextKey = pm === "unassigned" ? "queue:next:unassigned" : pm ? `queue:next:${pm}` : "queue:next";

  const currentNumber = (await redis.get<number>(currentKey)) ?? 0;
  const nextNumber = (await redis.get<number>(nextKey)) ?? (currentNumber + 1);
  const lastTicket = (await redis.get<number>("queue:last")) ?? 0;

  if (nextNumber > lastTicket) {
    return NextResponse.json({ currentNumber, nextNumber, message: "No more tickets", pm });
  }

  // 設置 currentNumber = nextNumber，然後 nextNumber = nextNumber + 1
  await redis.mset({
    [currentKey]: nextNumber,
    [nextKey]: nextNumber + 1,
  });

  return NextResponse.json({ currentNumber: nextNumber, nextNumber: nextNumber + 1, pm });
}
