import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const pm = url.searchParams.get("pm"); // pm can be a username or "unassigned" or null for all

  const lastTicket = (await redis.get<number>("queue:last")) ?? 0;

  if (pm) {
    // Get state for specific PM
    if (pm === "unassigned") {
      // For unassigned, we need to calculate from tickets without assignee
      const currentRaw = (await redis.get<number>("queue:current:unassigned")) ?? 0;
      const nextRaw = (await redis.get<number>("queue:next:unassigned"));
      const currentNumber = currentRaw;
      const nextNumber = nextRaw ?? (currentNumber + 1);
      return NextResponse.json({ currentNumber, lastTicket, nextNumber, pm });
    } else {
      const currentRaw = (await redis.get<number>(`queue:current:${pm}`)) ?? 0;
      const nextRaw = (await redis.get<number>(`queue:next:${pm}`));
      const currentNumber = currentRaw;
      const nextNumber = nextRaw ?? (currentNumber + 1);
      return NextResponse.json({ currentNumber, lastTicket, nextNumber, pm });
    }
  }

  // Legacy: return all PMs' states
  const [currentRaw, lastRaw] = await redis.mget<number[]>([
    "queue:current",
    "queue:last",
  ]);
  const currentNumber = currentRaw ?? 0;
  const nextNumber = (await redis.get<number>("queue:next")) ?? (currentNumber + 1);

  return NextResponse.json({ currentNumber, lastTicket, nextNumber });
}

export async function PATCH(request: Request) {
  try {
    const body = await request.json();
    const { currentNumber, nextNumber, pm } = body;

    const updates: Record<string, number> = {};

    // Determine the key prefix based on PM
    const keyPrefix = pm === "unassigned" ? "queue:current:unassigned" : pm ? `queue:current:${pm}` : "queue:current";
    const nextKeyPrefix = pm === "unassigned" ? "queue:next:unassigned" : pm ? `queue:next:${pm}` : "queue:next";

    if (currentNumber !== undefined && currentNumber !== null) {
      const numberValue = Number(currentNumber);
      if (isNaN(numberValue)) {
        return NextResponse.json(
          { error: "目前號碼必須是有效的數字" },
          { status: 400 }
        );
      }
      updates[keyPrefix] = numberValue;
    }

    if (nextNumber !== undefined && nextNumber !== null) {
      const numberValue = Number(nextNumber);
      if (isNaN(numberValue)) {
        return NextResponse.json(
          { error: "下一號必須是有效的數字" },
          { status: 400 }
        );
      }
      updates[nextKeyPrefix] = numberValue;
    }

    if (Object.keys(updates).length === 0) {
      return NextResponse.json(
        { error: "請提供目前號碼或下一號" },
        { status: 400 }
      );
    }

    // 不套用跳號邏輯，允許設置任何值
    await redis.mset(updates);

    const current = updates[keyPrefix] ?? (await redis.get<number>(keyPrefix)) ?? 0;
    const next = updates[nextKeyPrefix] ?? (await redis.get<number>(nextKeyPrefix)) ?? (current + 1);
    const lastTicket = (await redis.get<number>("queue:last")) ?? 0;

    return NextResponse.json({ currentNumber: current, lastTicket, nextNumber: next, pm });
  } catch (error) {
    console.error("Error updating state:", error);
    return NextResponse.json(
      { error: "更新狀態時發生錯誤" },
      { status: 500 }
    );
  }
}
