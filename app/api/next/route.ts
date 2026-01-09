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
  const lastTicket = (await redis.get<number>("queue:last")) ?? 0;

  // Get all ticket numbers
  const raw = await redis.lrange<number>("queue:tickets", 0, -1);
  const ticketNumbers: number[] = (raw ?? [])
    .map((x: any) => Number(x))
    .filter((n) => Number.isFinite(n));

  if (ticketNumbers.length === 0) {
    return NextResponse.json({ currentNumber, nextNumber: 1, message: "No tickets available", pm });
  }

  // Get assigned tickets for this PM
  const assignedTickets: number[] = [];
  for (const ticketNumber of ticketNumbers) {
    const key = `queue:ticket:${ticketNumber}`;
    const assignee = await redis.hget<string>(key, "assignee");
    
    if (pm === "unassigned") {
      // For unassigned, get tickets with no assignee or empty assignee
      if (!assignee || assignee === "") {
        assignedTickets.push(ticketNumber);
      }
    } else if (pm) {
      // For specific PM, get tickets assigned to this PM
      if (assignee === pm) {
        assignedTickets.push(ticketNumber);
      }
    } else {
      // For global (no PM specified), use all tickets
      assignedTickets.push(ticketNumber);
    }
  }

  // Sort assigned tickets in ascending order
  assignedTickets.sort((a, b) => a - b);

  if (assignedTickets.length === 0) {
    return NextResponse.json({ currentNumber, nextNumber: 1, message: "No assigned tickets", pm });
  }

  // Find current number's position in assigned tickets
  let currentIndex = assignedTickets.findIndex(num => num === currentNumber);
  
  // If current number is not in the list or is the last one, start from the first
  if (currentIndex === -1 || currentIndex === assignedTickets.length - 1) {
    const newCurrent = assignedTickets[0];
    const newNext = assignedTickets.length > 1 ? assignedTickets[1] : newCurrent;
    
    await redis.mset({
      [currentKey]: newCurrent,
      [nextKey]: newNext,
    });

    return NextResponse.json({ currentNumber: newCurrent, nextNumber: newNext, pm });
  }

  // Move to next assigned ticket
  const newCurrent = assignedTickets[currentIndex + 1];
  const newNext = currentIndex + 2 < assignedTickets.length ? assignedTickets[currentIndex + 2] : newCurrent;

  await redis.mset({
    [currentKey]: newCurrent,
    [nextKey]: newNext,
  });

  return NextResponse.json({ currentNumber: newCurrent, nextNumber: newNext, pm });
}
