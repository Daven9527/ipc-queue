import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      applicant,
      customerName,
      customerRequirement,
      machineType,
      startDate,
      expectedCompletionDate,
      fcst,
      massProductionDate,
    } = body;

    // Validate required fields
    if (
      !applicant ||
      !customerName ||
      !customerRequirement ||
      !machineType ||
      !startDate ||
      !expectedCompletionDate ||
      !fcst ||
      !massProductionDate
    ) {
      return NextResponse.json(
        { error: "所有欄位都是必填的" },
        { status: 400 }
      );
    }

    // Increment last ticket number and add to tickets list
    const ticketNumber = await redis.incr("queue:last");
    await redis.rpush("queue:tickets", ticketNumber);

    // Store ticket info in Redis Hash
    const key = `queue:ticket:${ticketNumber}`;
    await redis.hset(key, {
      applicant,
      customerName,
      customerRequirement,
      machineType,
      startDate,
      expectedCompletionDate,
      fcst,
      massProductionDate,
      status: "pending",
      note: "",
      assignee: "",
    });

    return NextResponse.json({ ticketNumber });
  } catch (error) {
    return NextResponse.json(
      { error: "處理請求時發生錯誤" },
      { status: 500 }
    );
  }
}
