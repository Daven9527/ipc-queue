import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

export async function POST() {
  const currentNumber = (await redis.get<number>("queue:current")) ?? 0;
  const nextNumber = (await redis.get<number>("queue:next")) ?? (currentNumber + 1);
  const lastTicket = (await redis.get<number>("queue:last")) ?? 0;

  if (nextNumber > lastTicket) {
    return NextResponse.json({ currentNumber, nextNumber, message: "No more tickets" });
  }

  // 設置 currentNumber = nextNumber，然後 nextNumber = nextNumber + 1
  await redis.mset({
    "queue:current": nextNumber,
    "queue:next": nextNumber + 1,
  });

  return NextResponse.json({ currentNumber: nextNumber, nextNumber: nextNumber + 1 });
}
