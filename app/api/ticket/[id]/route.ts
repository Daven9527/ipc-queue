import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

type TicketStatus = "pending" | "processing" | "replied" | "completed" | "cancelled";

interface TicketInfo {
  ticketNumber: number;
  applicant?: string;
  customerName?: string;
  customerRequirement?: string;
  machineType?: string;
  startDate?: string;
  expectedCompletionDate?: string;
  replyDate?: string;
  fcst?: string;
  massProductionDate?: string;
  status: TicketStatus;
  note: string;
  assignee?: string;
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const ticketNumber = parseInt(id);
    if (isNaN(ticketNumber)) {
      return NextResponse.json({ error: "無效的票號" }, { status: 400 });
    }

    const key = `queue:ticket:${ticketNumber}`;
    const data = await redis.hgetall<{
      applicant?: string;
      customerName?: string;
      customerRequirement?: string;
      machineType?: string;
      startDate?: string;
      expectedCompletionDate?: string;
      replyDate?: string;
      fcst?: string;
      massProductionDate?: string;
      status?: string;
      note?: string;
      assignee?: string;
    }>(key);

    if (!data || Object.keys(data).length === 0) {
      // Return default values if ticket info doesn't exist
      return NextResponse.json({
        ticketNumber,
        status: "pending" as TicketStatus,
        note: "",
        assignee: "",
        applicant: "",
        expectedCompletionDate: "",
        replyDate: "",
        fcst: "",
        massProductionDate: "",
      });
    }

    return NextResponse.json({
      ticketNumber,
      applicant: data.applicant || "",
      customerName: data.customerName || "",
      customerRequirement: data.customerRequirement || "",
      machineType: data.machineType || "",
      startDate: data.startDate || "",
      expectedCompletionDate: data.expectedCompletionDate || "",
      replyDate: data.replyDate || "",
      fcst: data.fcst || "",
      massProductionDate: data.massProductionDate || "",
      status: (data?.status || "pending") as TicketStatus,
      note: data?.note || "",
      assignee: data?.assignee || "",
    });
  } catch (error) {
    return NextResponse.json(
      { error: "處理請求時發生錯誤" },
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const ticketNumber = parseInt(id);
    if (isNaN(ticketNumber)) {
      return NextResponse.json({ error: "無效的票號" }, { status: 400 });
    }

    const body = await request.json();
    const { status, note, assignee, fcst, massProductionDate } = body;

    const key = `queue:ticket:${ticketNumber}`;
    const updates: Record<string, string> = {};

    if (status !== undefined && status !== null) {
      if (!["pending", "processing", "replied", "completed", "cancelled"].includes(status)) {
        return NextResponse.json({ error: "無效的狀態" }, { status: 400 });
      }
      updates.status = String(status);
      if (status === "replied") {
        updates.replyDate = new Date().toISOString();
      }
    }

    if (note !== undefined && note !== null) {
      updates.note = String(note);
    }

    if (assignee !== undefined && assignee !== null) {
      updates.assignee = String(assignee);
    }

    if (fcst !== undefined && fcst !== null) {
      updates.fcst = String(fcst);
    }

    if (massProductionDate !== undefined && massProductionDate !== null) {
      updates.massProductionDate = String(massProductionDate);
    }

    if (Object.keys(updates).length > 0) {
      await redis.hset(key, updates);
    }

    // Return updated ticket info with all fields
    const data = await redis.hgetall<{
      applicant?: string;
      customerName?: string;
      customerRequirement?: string;
      machineType?: string;
      startDate?: string;
      expectedCompletionDate?: string;
      replyDate?: string;
      fcst?: string;
      massProductionDate?: string;
      status?: string;
      note?: string;
      assignee?: string;
    }>(key);
    
    return NextResponse.json({
      ticketNumber,
      applicant: data?.applicant || "",
      customerName: data?.customerName || "",
      customerRequirement: data?.customerRequirement || "",
      machineType: data?.machineType || "",
      startDate: data?.startDate || "",
      expectedCompletionDate: data?.expectedCompletionDate || "",
      replyDate: data?.replyDate || "",
      fcst: data?.fcst || "",
      massProductionDate: data?.massProductionDate || "",
      status: (data?.status || "pending") as TicketStatus,
      note: data?.note || "",
      assignee: data?.assignee || "",
    });
  } catch (error) {
    console.error("Error updating ticket:", error);
    return NextResponse.json(
      { error: "處理請求時發生錯誤" },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const ticketNumber = parseInt(id);
    if (isNaN(ticketNumber)) {
      return NextResponse.json({ error: "無效的票號" }, { status: 400 });
    }

    // Delete ticket info hash
    const key = `queue:ticket:${ticketNumber}`;
    await redis.del(key);

    // Remove ticket number from tickets list
    // Get all ticket numbers, filter out the one to delete, then replace the list
    const allTickets = await redis.lrange<number>("queue:tickets", 0, -1);
    const filteredTickets = (allTickets || [])
      .map((t: any) => Number(t))
      .filter((n: number) => n !== ticketNumber && Number.isFinite(n));
    
    // Delete the old list and recreate it with filtered values
    await redis.del("queue:tickets");
    if (filteredTickets.length > 0) {
      await redis.rpush("queue:tickets", ...filteredTickets);
    }

    return NextResponse.json({ ok: true, ticketNumber });
  } catch (error) {
    console.error("Error deleting ticket:", error);
    return NextResponse.json(
      { error: "處理請求時發生錯誤" },
      { status: 500 }
    );
  }
}

