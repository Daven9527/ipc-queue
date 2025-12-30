// In-memory store for queue system
let currentNumber = 0;
let lastTicket = 0;

export type TicketStatus = "pending" | "processing" | "completed" | "cancelled";

export interface TicketInfo {
  ticketNumber: number;
  customerName: string;
  customerRequirement: string;
  machineType: string;
  startDate: string;
  status: TicketStatus;
  reply: string;
}

const tickets: Map<number, TicketInfo> = new Map();

export interface QueueState {
  currentNumber: number;
  lastTicket: number;
}

export function getState(): QueueState {
  return {
    currentNumber,
    lastTicket,
  };
}

export function issueTicket(info: {
  customerName: string;
  customerRequirement: string;
  machineType: string;
  startDate: string;
}): number {
  lastTicket += 1;
  const ticket: TicketInfo = {
    ticketNumber: lastTicket,
    ...info,
    status: "pending",
    reply: "",
  };
  tickets.set(lastTicket, ticket);
  return lastTicket;
}

export function getTicket(ticketNumber: number): TicketInfo | undefined {
  return tickets.get(ticketNumber);
}

export function getAllTickets(): TicketInfo[] {
  return Array.from(tickets.values()).sort((a, b) => a.ticketNumber - b.ticketNumber);
}

export function nextNumber(): number {
  if (currentNumber < lastTicket) {
    currentNumber += 1;
  }
  return currentNumber;
}

export function updateTicket(
  ticketNumber: number,
  updates: Partial<Pick<TicketInfo, "status" | "reply">>
): boolean {
  const ticket = tickets.get(ticketNumber);
  if (!ticket) return false;

  tickets.set(ticketNumber, {
    ...ticket,
    ...updates,
  });
  return true;
}

export function reset(): void {
  currentNumber = 0;
  lastTicket = 0;
  tickets.clear();
}

