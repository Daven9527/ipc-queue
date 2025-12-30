import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

export async function GET() {
  const [currentRaw, lastRaw] = await redis.mget<number[]>([
    "queue:current",
    "queue:last",
  ]);
  const currentNumber = currentRaw ?? 0;
  const lastTicket = lastRaw ?? 0;
  const nextNumber = (await redis.get<number>("queue:next")) ?? (currentNumber + 1);

  return NextResponse.json({ currentNumber, lastTicket, nextNumber });
}

export async function PATCH(request: Request) {
  try {
    const body = await request.json();
    const { currentNumber, nextNumber } = body;

    const updates: Record<string, number> = {};

    if (currentNumber !== undefined && currentNumber !== null) {
      const numberValue = Number(currentNumber);
      if (isNaN(numberValue)) {
        return NextResponse.json(
          { error: "目前號碼必須是有效的數字" },
          { status: 400 }
        );
      }
      updates["queue:current"] = numberValue;
    }

    if (nextNumber !== undefined && nextNumber !== null) {
      const numberValue = Number(nextNumber);
      if (isNaN(numberValue)) {
        return NextResponse.json(
          { error: "下一號必須是有效的數字" },
          { status: 400 }
        );
      }
      updates["queue:next"] = numberValue;
    }

    if (Object.keys(updates).length === 0) {
      return NextResponse.json(
        { error: "請提供目前號碼或下一號" },
        { status: 400 }
      );
    }

    // 不套用跳號邏輯，允許設置任何值
    await redis.mset(updates);

    const current = updates["queue:current"] ?? (await redis.get<number>("queue:current")) ?? 0;
    const next = updates["queue:next"] ?? (await redis.get<number>("queue:next")) ?? (current + 1);
    const lastTicket = (await redis.get<number>("queue:last")) ?? 0;

    return NextResponse.json({ currentNumber: current, lastTicket, nextNumber: next });
  } catch (error) {
    console.error("Error updating state:", error);
    return NextResponse.json(
      { error: "更新狀態時發生錯誤" },
      { status: 500 }
    );
  }
}
