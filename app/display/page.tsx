"use client";

import { useState, useEffect } from "react";

interface QueueState {
  currentNumber: number;
  lastTicket: number;
  nextNumber?: number;
}

type TicketStatus = "pending" | "processing" | "replied" | "completed" | "cancelled";

interface TicketInfo {
  ticketNumber: number;
  applicant?: string;
  customerName?: string;
  customerRequirement?: string;
  machineType?: string;
  startDate?: string;
  expectedCompletionDate?: string;
  status: TicketStatus;
  note: string;
  assignee?: string;
  replyDate?: string;
  fcst?: string;
  massProductionDate?: string;
}

interface TicketListResponse {
  tickets: TicketInfo[];
}

const statusLabels: Record<TicketStatus, string> = {
  pending: "等待中",
  processing: "處理中",
  replied: "已回覆",
  completed: "已完成",
  cancelled: "已取消",
};

const statusColors: Record<TicketStatus, string> = {
  pending: "bg-yellow-500 text-white",
  processing: "bg-blue-500 text-white",
  replied: "bg-indigo-500 text-white",
  completed: "bg-green-500 text-white",
  cancelled: "bg-red-500 text-white",
};

const taiwanDateFormatter = new Intl.DateTimeFormat("en-CA", {
  timeZone: "Asia/Taipei",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
});

const getTaiwanDayIndex = (date: Date): number => {
  const parts = taiwanDateFormatter.formatToParts(date);
  const year = Number(parts.find((p) => p.type === "year")?.value);
  const month = Number(parts.find((p) => p.type === "month")?.value);
  const day = Number(parts.find((p) => p.type === "day")?.value);

  if (!year || !month || !day) return NaN;
  return Date.UTC(year, month - 1, day) / 86400000;
};

const calculateTaiwanDayDiff = (replyDate: string): number => {
  const parsed = new Date(replyDate);
  if (Number.isNaN(parsed.getTime())) return 0;

  const diffDays = Math.floor(getTaiwanDayIndex(new Date()) - getTaiwanDayIndex(parsed));
  return Number.isFinite(diffDays) ? Math.max(0, diffDays) : 0;
};



export default function DisplayPage() {
  const [state, setState] = useState<QueueState>({ currentNumber: 0, lastTicket: 0, nextNumber: 1 });
  const [tickets, setTickets] = useState<TicketInfo[]>([]);
  const [viewingTicket, setViewingTicket] = useState<TicketInfo | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [refreshMessage, setRefreshMessage] = useState<string | null>(null);

  useEffect(() => {
    const fetchInitial = async () => {
      try {
        const [stateRes, ticketsRes] = await Promise.all([
          fetch("/api/state", { cache: "no-store" }),
          fetch("/api/tickets?limit=50", { cache: "no-store" }),
        ]);

        const stateData = await stateRes.json();
        const ticketsData: TicketListResponse = await ticketsRes.json();

        setState(stateData);
        setTickets(ticketsData.tickets || []);
      } catch (error) {
        console.error("Failed to fetch data:", error);
      }
    };

    fetchInitial();
  }, []);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    setRefreshMessage(null);
    try {
      const [stateRes, ticketsRes] = await Promise.all([
        fetch("/api/state", { cache: "no-store" }),
        fetch("/api/tickets?limit=50", { cache: "no-store" }),
      ]);
      if (!stateRes.ok) throw new Error("狀態取得失敗");
      if (!ticketsRes.ok) throw new Error("號碼列表取得失敗");
      const stateData: QueueState = await stateRes.json();
      const ticketsData: TicketListResponse = await ticketsRes.json();
      setState(stateData);
      setTickets(ticketsData.tickets || []);
      setRefreshMessage("已更新");
      setTimeout(() => setRefreshMessage(null), 2000);
    } catch (error) {
      console.error("Manual refresh failed:", error);
      setRefreshMessage("更新失敗");
      setTimeout(() => setRefreshMessage(null), 2000);
    } finally {
      setIsRefreshing(false);
    }
  };

  const nextNumber = state.nextNumber ?? (state.currentNumber < state.lastTicket ? state.currentNumber + 1 : null);
  
  // Find current ticket info
  const currentTicket = tickets.find((t) => t.ticketNumber === state.currentNumber);

  // Sort tickets in ascending order (oldest first)
  const sortedTickets = [...tickets].sort((a, b) => a.ticketNumber - b.ticketNumber);

  const isCurrentNumber = (ticketNumber: number) => ticketNumber === state.currentNumber;
  const isCalled = (ticketNumber: number) => ticketNumber <= state.currentNumber;

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 p-4 md:p-8">
      <div className="w-full max-w-7xl mx-auto">
        {/* 返回主頁按鈕 */}
        <div className="mb-4 md:mb-6 text-center">
          <a
            href="/"
            className="inline-block px-4 md:px-6 py-2 md:py-3 bg-white/10 hover:bg-white/20 backdrop-blur-sm rounded-lg text-white font-medium transition-colors text-sm md:text-base"
          >
            返回主頁
          </a>
        </div>

        <div className="mb-4 md:mb-6 flex flex-col md:flex-row items-center justify-center gap-3 md:gap-4">
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm md:text-base px-3 md:px-4 py-2 font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isRefreshing ? "更新中…" : "更新狀態"}
          </button>
          {refreshMessage && (
            <span className="text-sm md:text-base text-gray-200">
              {refreshMessage}
            </span>
          )}
        </div>

        {/* 目前叫號區塊 */}
        <div className="mb-6 md:mb-8">
          <h1 className="text-2xl md:text-4xl lg:text-5xl font-bold text-white mb-6 md:mb-8 text-center">目前叫號</h1>
          
          <div className="bg-white rounded-2xl shadow-2xl p-6 md:p-12 lg:p-16 mb-6 md:mb-8">
            <p className="text-xl md:text-2xl lg:text-3xl text-gray-600 mb-4 md:mb-6 text-center">現在服務</p>
            <div className="text-6xl md:text-8xl lg:text-9xl font-bold text-blue-600 mb-4 md:mb-6 text-center">
              {state.currentNumber === 0 ? "—" : state.currentNumber}
            </div>
            
            {/* 顯示目前號碼的狀態和備註 */}
            {state.currentNumber > 0 && (
              <div className="mt-6 md:mt-8 space-y-4 md:space-y-5">
                {/* 處理進度 */}
                {currentTicket ? (
                  <div className="flex flex-col items-center gap-3 md:gap-4">
                    <p className="text-base md:text-lg text-gray-600 font-medium">處理進度</p>
                    <div className={`inline-block px-5 md:px-7 py-2.5 md:py-3.5 rounded-full text-base md:text-lg font-semibold ${
                      currentTicket.status === "processing"
                        ? "bg-blue-500 text-white"
                        : currentTicket.status === "replied"
                        ? "bg-indigo-500 text-white"
                        : currentTicket.status === "completed"
                        ? "bg-green-500 text-white"
                        : currentTicket.status === "cancelled"
                        ? "bg-red-500 text-white"
                        : "bg-yellow-500 text-white"
                    }`}>
                      {statusLabels[currentTicket.status]}
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-3 md:gap-4">
                    <p className="text-base md:text-lg text-gray-600 font-medium">處理進度</p>
                    <div className="inline-block px-5 md:px-7 py-2.5 md:py-3.5 rounded-full text-base md:text-lg font-semibold bg-gray-400 text-white">
                      處理中
                    </div>
                  </div>
                )}
                
                {/* PM 備註 */}
                {currentTicket?.note && (
                  <div className="mt-4 md:mt-6 p-5 md:p-6 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border-2 border-blue-200 text-left max-w-3xl mx-auto shadow-md">
                    <div className="flex items-center gap-2 mb-3">
                      <svg className="w-5 h-5 md:w-6 md:h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                      </svg>
                      <p className="text-base md:text-lg font-bold text-blue-900">PM 備註</p>
                    </div>
                    <p className="text-sm md:text-base text-gray-800 whitespace-pre-wrap break-words leading-relaxed">
                      {currentTicket.note}
                    </p>
                  </div>
                )}

                {/* PM */}
                {currentTicket?.assignee && (
                  <div className="mt-4 md:mt-6 p-5 md:p-6 bg-gradient-to-r from-purple-50 to-pink-50 rounded-xl border-2 border-purple-200 text-left max-w-3xl mx-auto shadow-md">
                    <div className="flex items-center gap-2 mb-3">
                      <svg className="w-5 h-5 md:w-6 md:h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                      </svg>
                      <p className="text-base md:text-lg font-bold text-purple-900">PM</p>
                    </div>
                    <p className="text-sm md:text-base text-gray-800 break-words leading-relaxed">
                      {currentTicket.assignee}
                    </p>
                  </div>
                )}


                {/* 期望完成日期 */}
                {currentTicket?.expectedCompletionDate && (
                  <div className="mt-4 md:mt-6 p-5 md:p-6 bg-gradient-to-r from-green-50 to-emerald-50 rounded-xl border-2 border-green-200 text-left max-w-3xl mx-auto shadow-md">
                    <div className="flex items-center gap-2 mb-3">
                      <svg className="w-5 h-5 md:w-6 md:h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                      </svg>
                      <p className="text-base md:text-lg font-bold text-green-900">期望完成日期</p>
                    </div>
                    <p className="text-sm md:text-base text-gray-800 break-words leading-relaxed">
                      {currentTicket.expectedCompletionDate}
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          {nextNumber && (
            <div className="bg-white/10 backdrop-blur-sm rounded-2xl shadow-xl p-4 md:p-6 lg:p-8 mb-4 md:mb-6 text-center">
              <p className="text-lg md:text-xl lg:text-2xl text-gray-300 mb-3 md:mb-4">下一位</p>
              <div className="text-4xl md:text-5xl lg:text-7xl font-bold text-yellow-400">
                {nextNumber}
              </div>
            </div>
          )}

          {state.currentNumber === 0 && state.lastTicket === 0 && (
            <div className="bg-white/10 backdrop-blur-sm rounded-2xl shadow-xl p-6 md:p-8 lg:p-12 text-center">
              <p className="text-lg md:text-xl lg:text-2xl text-gray-300">等待中...</p>
            </div>
          )}
        </div>

        {/* 所有號碼列表 */}
        {sortedTickets.length > 0 && (
          <div className="bg-white/10 backdrop-blur-sm rounded-2xl shadow-xl p-4 md:p-6">
            <h2 className="text-xl md:text-2xl lg:text-3xl font-bold text-white mb-4 md:mb-6 text-center">所有號碼狀態</h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3 md:gap-4">
              {sortedTickets.map((ticket) => (
                <div
                  key={ticket.ticketNumber}
                  onClick={() => setViewingTicket(ticket)}
                  className={`rounded-lg border-2 p-3 md:p-4 transition-all text-center cursor-pointer hover:scale-105 ${
                    isCurrentNumber(ticket.ticketNumber)
                      ? "border-blue-500 bg-blue-500/20 backdrop-blur-sm"
                      : isCalled(ticket.ticketNumber)
                      ? "border-gray-400 bg-gray-500/20 backdrop-blur-sm"
                      : "border-gray-300 bg-white/10 backdrop-blur-sm"
                  }`}
                >
                  <div
                    className={`text-lg md:text-xl font-bold mb-2 ${
                      isCurrentNumber(ticket.ticketNumber)
                        ? "text-blue-300"
                        : isCalled(ticket.ticketNumber)
                        ? "text-gray-300"
                        : "text-white"
                    }`}
                  >
                    #{ticket.ticketNumber}
                  </div>
                  <div className={`inline-block px-2 md:px-3 py-1 rounded-full text-xs md:text-sm font-medium mb-2 ${statusColors[ticket.status]}`}>
                    {statusLabels[ticket.status]}
                  </div>
                  {isCurrentNumber(ticket.ticketNumber) && (
                    <div className="mt-2 px-2 py-1 rounded-full bg-blue-600 text-white text-xs font-medium">
                      目前號碼
                    </div>
                  )}
                  {ticket.applicant && (
                    <div className="mt-2 p-2 bg-green-500/30 rounded text-xs text-green-100 break-words">
                      申請人：{ticket.applicant}
                    </div>
                  )}
                  {ticket.note && (
                    <div className="mt-2 p-2 bg-black/20 rounded text-xs text-gray-200 break-words line-clamp-2">
                      {ticket.note}
                    </div>
                  )}
                  {ticket.assignee && (
                    <div className="mt-2 p-2 bg-purple-500/30 rounded text-xs text-purple-100 break-words">
                      PM：{ticket.assignee}
                    </div>
                  )}
                  {ticket.status === "replied" && ticket.replyDate && (
                    <div className="mt-2 p-2 bg-indigo-500/30 rounded text-xs text-indigo-100 break-words">
                      已回覆累積天數：{calculateTaiwanDayDiff(ticket.replyDate)} 天
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 彈窗：顯示完整票券資訊 */}
      {viewingTicket && (
        <div
          className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center p-4 z-50"
          onClick={() => setViewingTicket(null)}
        >
          <div
            className="bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 md:p-8">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl md:text-3xl font-bold text-gray-900">
                  號碼 #{viewingTicket.ticketNumber} 詳細資訊
                </h2>
                <button
                  onClick={() => setViewingTicket(null)}
                  className="text-gray-400 hover:text-gray-600 transition-colors"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              <div className="space-y-4 md:space-y-5">
                {/* 狀態 */}
                <div>
                  <p className="text-sm md:text-base font-medium text-gray-600 mb-2">處理進度</p>
                  <div className={`inline-block px-4 md:px-5 py-2 md:py-2.5 rounded-full text-sm md:text-base font-semibold ${
                    viewingTicket.status === "pending"
                      ? "bg-yellow-100 text-yellow-800"
                      : viewingTicket.status === "processing"
                      ? "bg-blue-100 text-blue-800"
                      : viewingTicket.status === "replied"
                      ? "bg-indigo-100 text-indigo-800"
                      : viewingTicket.status === "completed"
                      ? "bg-green-100 text-green-800"
                      : "bg-red-100 text-red-800"
                  }`}>
                    {statusLabels[viewingTicket.status]}
                  </div>
                </div>

                {/* 申請人 */}
                {viewingTicket.applicant && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">申請人</p>
                    <p className="text-base md:text-lg text-gray-900 break-words">{viewingTicket.applicant}</p>
                  </div>
                )}

                {/* 客戶名稱 */}
                {viewingTicket.customerName && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">客戶名稱</p>
                    <p className="text-base md:text-lg text-gray-900 break-words">{viewingTicket.customerName}</p>
                  </div>
                )}

                {/* 客戶需求 */}
                {viewingTicket.customerRequirement && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">客戶需求</p>
                    <p className="text-base md:text-lg text-gray-900 break-words whitespace-pre-wrap bg-gray-50 p-3 md:p-4 rounded-lg">
                      {viewingTicket.customerRequirement}
                    </p>
                  </div>
                )}

                {/* 預計使用機種 */}
                {viewingTicket.machineType && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">預計使用機種</p>
                    <p className="text-base md:text-lg text-gray-900 break-words">{viewingTicket.machineType}</p>
                  </div>
                )}

                {/* 起始日期 */}
                {viewingTicket.startDate && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">起始日期</p>
                    <p className="text-base md:text-lg text-gray-900">{viewingTicket.startDate}</p>
                  </div>
                )}

                {/* 期望完成日期 */}
                {viewingTicket.expectedCompletionDate && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">期望完成日期</p>
                    <p className="text-base md:text-lg text-gray-900">{viewingTicket.expectedCompletionDate}</p>
                  </div>
                )}

                {/* PM 備註 */}
                {viewingTicket.note && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">PM 備註</p>
                    <p className="text-base md:text-lg text-gray-900 break-words whitespace-pre-wrap bg-blue-50 p-3 md:p-4 rounded-lg border-l-4 border-blue-500">
                      {viewingTicket.note}
                    </p>
                  </div>
                )}

                {/* PM */}
                {viewingTicket.assignee && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">PM</p>
                    <p className="text-base md:text-lg text-gray-900 break-words bg-purple-50 p-3 md:p-4 rounded-lg border-l-4 border-purple-500">
                      {viewingTicket.assignee}
                    </p>
                  </div>
                )}

                {/* FCST */}
                {viewingTicket.fcst && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">FCST</p>
                    <p className="text-base md:text-lg text-gray-900 break-words bg-yellow-50 p-3 md:p-4 rounded-lg border-l-4 border-yellow-500">
                      {viewingTicket.fcst}
                    </p>
                  </div>
                )}

                {/* 預計量產日 */}
                {viewingTicket.massProductionDate && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">預計量產日</p>
                    <p className="text-base md:text-lg text-gray-900 break-words bg-green-50 p-3 md:p-4 rounded-lg border-l-4 border-green-500">
                      {viewingTicket.massProductionDate}
                    </p>
                  </div>
                )}

                {/* 已回覆累積天數 */}
                {viewingTicket.status === "replied" && viewingTicket.replyDate && (
                  <div>
                    <p className="text-sm md:text-base font-medium text-gray-600 mb-2">已回覆累積天數</p>
                    <p className="text-base md:text-lg text-gray-900 break-words bg-indigo-50 p-3 md:p-4 rounded-lg border-l-4 border-indigo-500">
                      {calculateTaiwanDayDiff(viewingTicket.replyDate)}{" "}
                      天
                    </p>
                  </div>
                )}


                {/* 如果沒有客戶資訊，顯示提示 */}
                {!viewingTicket.customerName && !viewingTicket.customerRequirement && !viewingTicket.machineType && !viewingTicket.startDate && (
                  <div className="text-center py-8 text-gray-500">
                    <p className="text-sm md:text-base">此票券沒有客戶資訊</p>
                  </div>
                )}
              </div>

              <div className="mt-6 md:mt-8 flex gap-3">
                <button
                  onClick={() => setViewingTicket(null)}
                  className="flex-1 rounded-lg bg-gray-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium hover:bg-gray-700 transition-colors"
                >
                  關閉
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
