"use client";

import { useState, useEffect, useRef } from "react";

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
  fcst?: string;
  massProductionDate?: string;
  replyDate?: string;
  status: TicketStatus;
  note: string;
  assignee?: string;
}

interface TicketListResponse {
  tickets: TicketInfo[];
}

const ADMIN_PASSWORD = "Bailey";
const RESET_PASSWORD = "Eunice";

const statusLabels: Record<TicketStatus, string> = {
  pending: "等待中",
  processing: "處理中",
  replied: "已回覆",
  completed: "已完成",
  cancelled: "已取消",
};

const statusColors: Record<TicketStatus, string> = {
  pending: "bg-yellow-100 text-yellow-800",
  processing: "bg-blue-100 text-blue-800",
  replied: "bg-indigo-100 text-indigo-800",
  completed: "bg-green-100 text-green-800",
  cancelled: "bg-red-100 text-red-800",
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



export default function AdminPage() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [state, setState] = useState<QueueState>({ currentNumber: 0, lastTicket: 0, nextNumber: 1 });
  const [tickets, setTickets] = useState<TicketInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [editingTicket, setEditingTicket] = useState<number | null>(null);
  const [editStatus, setEditStatus] = useState<TicketStatus>("pending");
  const [editNote, setEditNote] = useState<string>("");
  const [editAssignee, setEditAssignee] = useState<string>("");
  const [viewingTicket, setViewingTicket] = useState<TicketInfo | null>(null);
  const [showSuperAdminModal, setShowSuperAdminModal] = useState(false);
  const [superAdminPassword, setSuperAdminPassword] = useState("");
  const [superAdminPasswordError, setSuperAdminPasswordError] = useState("");
  const [isSuperAdminAuthenticated, setIsSuperAdminAuthenticated] = useState(false);
  const [editingCurrentNumber, setEditingCurrentNumber] = useState(false);
  const [newCurrentNumber, setNewCurrentNumber] = useState<string>("");
  const [editingNextNumber, setEditingNextNumber] = useState(false);
  const [newNextNumber, setNewNextNumber] = useState<string>("");
  const editingTicketRef = useRef<number | null>(null);

  // Check if already authenticated (from sessionStorage)
  useEffect(() => {
    const authStatus = sessionStorage.getItem("adminAuthenticated");
    if (authStatus === "true") {
      setIsAuthenticated(true);
    }
  }, []);

  const handlePasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError("");

    if (password === ADMIN_PASSWORD) {
      setIsAuthenticated(true);
      sessionStorage.setItem("adminAuthenticated", "true");
      setPassword("");
    } else {
      setPasswordError("密碼錯誤，請重試");
      setPassword("");
    }
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    sessionStorage.removeItem("adminAuthenticated");
  };

  const fetchState = async () => {
    try {
      const res = await fetch("/api/state", { cache: "no-store" });
      const data = await res.json();
      setState(data);
    } catch (error) {
      console.error("Failed to fetch state:", error);
    }
  };

  const fetchTickets = async () => {
    try {
      const res = await fetch("/api/tickets?limit=50", { cache: "no-store" });
      const data: TicketListResponse = await res.json();
      setTickets(data.tickets || []);
    } catch (error) {
      console.error("Failed to fetch tickets:", error);
      setTickets([]);
    }
  };

  useEffect(() => {
    editingTicketRef.current = editingTicket;
  }, [editingTicket]);

  useEffect(() => {
    if (!isAuthenticated) return;
    fetchState();
    fetchTickets();
  }, [isAuthenticated]);

  const handleNext = async () => {
    setLoading(true);
    try {
      await fetch("/api/next", { method: "POST" });
      await fetchState();
      await fetchTickets();
    } catch (error) {
      console.error("Failed to call next:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleSuperAdminClick = () => {
    setShowSuperAdminModal(true);
    setSuperAdminPassword("");
    setSuperAdminPasswordError("");
    setIsSuperAdminAuthenticated(false);
  };

  const handleSuperAdminPasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSuperAdminPasswordError("");

    if (superAdminPassword === RESET_PASSWORD) {
      setIsSuperAdminAuthenticated(true);
      setSuperAdminPassword("");
    } else {
      setSuperAdminPasswordError("密碼錯誤，請重試");
      setSuperAdminPassword("");
    }
  };

  const handleSuperAdminCancel = () => {
    setShowSuperAdminModal(false);
    setSuperAdminPassword("");
    setSuperAdminPasswordError("");
    setIsSuperAdminAuthenticated(false);
  };

  const handleResetClick = () => {
    if (!confirm("確定要重置系統嗎？此操作將清除所有號碼和資料，且無法復原。")) {
      return;
    }
    
    // 關閉超級管理員彈窗
    handleSuperAdminCancel();
    
    // 直接執行重置，因為已經在超級管理員彈窗中驗證過密碼
    setLoading(true);
    (async () => {
      try {
        await fetch("/api/reset", { method: "POST" });
        await fetchState();
        await fetchTickets();
        alert("系統已重置");
      } catch (error) {
        console.error("Failed to reset:", error);
        alert("重置失敗，請重試");
      } finally {
        setLoading(false);
      }
    })();
  };


  const handleUpdateCurrentNumber = async () => {
    const numberValue = Number(newCurrentNumber);
    if (isNaN(numberValue)) {
      alert("請輸入有效的數字");
      return;
    }

    // 不套用跳號邏輯，允許設置任何值
    setLoading(true);
    try {
      const res = await fetch("/api/state", {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ currentNumber: numberValue }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "更新失敗");
      }

      setEditingCurrentNumber(false);
      setNewCurrentNumber("");
      await fetchState();
      await fetchTickets();
    } catch (error) {
      console.error("Failed to update current number:", error);
      alert(error instanceof Error ? error.message : "更新失敗，請重試");
    } finally {
      setLoading(false);
    }
  };

  const handleCancelEditCurrentNumber = () => {
    setEditingCurrentNumber(false);
    setNewCurrentNumber("");
  };

  const handleUpdateNextNumber = async () => {
    const nextNumberValue = Number(newNextNumber);
    if (isNaN(nextNumberValue)) {
      alert("請輸入有效的數字");
      return;
    }

    // 只更新下一號，不改變目前號碼
    setLoading(true);
    try {
      const res = await fetch("/api/state", {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ nextNumber: nextNumberValue }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "更新失敗");
      }

      setEditingNextNumber(false);
      setNewNextNumber("");
      await fetchState();
      await fetchTickets();
    } catch (error) {
      console.error("Failed to update next number:", error);
      alert(error instanceof Error ? error.message : "更新失敗，請重試");
    } finally {
      setLoading(false);
    }
  };

  const handleCancelEditNextNumber = () => {
    setEditingNextNumber(false);
    setNewNextNumber("");
  };

  const handleExportExcel = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/export");
      
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "匯出失敗");
      }

      // 獲取文件名
      const contentDisposition = res.headers.get("Content-Disposition");
      let fileName = "票券資料.xlsx";
      if (contentDisposition) {
        const fileNameMatch = contentDisposition.match(/filename="?(.+)"?/);
        if (fileNameMatch) {
          fileName = decodeURIComponent(fileNameMatch[1]);
        }
      }

      // 下載文件
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error("Failed to export:", error);
      alert(error instanceof Error ? error.message : "匯出失敗，請重試");
    } finally {
      setLoading(false);
    }
  };

  const handleImportExcel = async () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".xlsx,.xls";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      setLoading(true);
      try {
        const formData = new FormData();
        formData.append("file", file);
        formData.append("password", RESET_PASSWORD);

        const res = await fetch("/api/import", {
          method: "POST",
          body: formData,
        });

        const data = await res.json();

        if (!res.ok) {
          throw new Error(data.error || "匯入失敗");
        }

        // 顯示匯入結果
        let message = `匯入完成！\n新增：${data.imported} 筆\n更新：${data.updated} 筆`;
        if (data.errors && data.errors.length > 0) {
          message += `\n\n錯誤：\n${data.errors.slice(0, 10).join("\n")}`;
          if (data.errors.length > 10) {
            message += `\n... 還有 ${data.errors.length - 10} 個錯誤`;
          }
        }
        alert(message);

        // 刷新資料
        await fetchState();
        await fetchTickets();
      } catch (error) {
        console.error("Failed to import:", error);
        alert(error instanceof Error ? error.message : "匯入失敗，請重試");
      } finally {
        setLoading(false);
      }
    };
    input.click();
  };

  const startEdit = (ticket: TicketInfo) => {
    setEditingTicket(ticket.ticketNumber);
    setEditStatus(ticket.status);
    setEditNote(ticket.note);
    setEditAssignee(ticket.assignee || "");
  };

  const cancelEdit = () => {
    setEditingTicket(null);
    setEditStatus("pending");
    setEditNote("");
    setEditAssignee("");
    editingTicketRef.current = null;
  };

  const saveEdit = async (ticketNumber: number) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/ticket/${ticketNumber}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          status: editStatus,
          note: editNote,
          assignee: editAssignee,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "更新失敗");
      }

      // Clear editing state first to allow refresh
      cancelEdit();
      
      // Force refresh tickets to show updated data
      await fetchTickets();
    } catch (error) {
      console.error("Failed to update ticket:", error);
      alert(error instanceof Error ? error.message : "更新失敗，請重試");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (ticketNumber: number) => {
    if (!confirm(`確定要刪除號碼 #${ticketNumber} 嗎？此操作無法復原。`)) {
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`/api/ticket/${ticketNumber}`, {
        method: "DELETE",
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "刪除失敗");
      }

      // Refresh tickets and state
      await fetchTickets();
      await fetchState();
    } catch (error) {
      console.error("Failed to delete ticket:", error);
      alert(error instanceof Error ? error.message : "刪除失敗，請重試");
    } finally {
      setLoading(false);
    }
  };

  // Password authentication screen
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="bg-white rounded-xl shadow-lg p-8">
            <h1 className="text-2xl md:text-3xl font-bold text-gray-900 mb-6 text-center">管理員登入</h1>
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                  密碼
                </label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    setPasswordError("");
                  }}
                  className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
                  placeholder="請輸入密碼"
                  autoFocus
                />
              </div>
              {passwordError && (
                <div className="rounded-lg bg-red-50 border border-red-200 p-3">
                  <p className="text-sm text-red-600">{passwordError}</p>
                </div>
              )}
              <button
                type="submit"
                className="w-full rounded-lg bg-blue-600 px-6 py-3 text-white font-medium shadow-md hover:bg-blue-700 transition-colors"
              >
                登入
              </button>
            </form>
            <div className="mt-6 text-center">
              <a
                href="/"
                className="text-sm text-blue-600 hover:text-blue-800 underline"
              >
                返回首頁
              </a>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const waitingCount = tickets.filter(ticket => ticket.status === "pending").length;
  const isCurrentNumber = (ticketNumber: number) => ticketNumber === state.currentNumber;
  const isCalled = (ticketNumber: number) => ticketNumber <= state.currentNumber;

  // Sort tickets in descending order (newest first)
  const sortedTickets = [...tickets].sort((a, b) => b.ticketNumber - a.ticketNumber);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 p-3 md:p-8">
      <div className="mx-auto max-w-7xl">
        <div className="mb-6 md:mb-8 text-center">
          <div className="flex items-center justify-between mb-2">
            <div className="flex-1"></div>
            <h1 className="text-2xl md:text-4xl font-bold text-gray-900 flex-1">管理員控制台</h1>
            <div className="flex-1 flex justify-end">
              <button
                onClick={handleLogout}
                className="rounded-lg bg-gray-600 px-4 py-2 text-sm md:text-base text-white font-medium hover:bg-gray-700 transition-colors"
              >
                登出
              </button>
            </div>
          </div>
          <p className="text-sm md:text-base text-gray-600">叫號系統管理</p>
        </div>

        {/* 狀態和操作卡片 */}
        <div className="grid gap-4 md:gap-6 md:grid-cols-2 mb-6 md:mb-8">
          <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
            <h2 className="mb-3 md:mb-4 text-lg md:text-xl font-semibold text-gray-800">目前狀態</h2>
            <div className="space-y-3 md:space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs md:text-sm text-gray-600">目前叫到的號碼</p>
                  {!editingCurrentNumber && (
                    <button
                      onClick={() => {
                        setEditingCurrentNumber(true);
                        setNewCurrentNumber(String(state.currentNumber));
                      }}
                      className="text-xs md:text-sm text-blue-600 hover:text-blue-800 underline"
                    >
                      編輯
                    </button>
                  )}
                </div>
                {editingCurrentNumber ? (
                  <div className="space-y-2">
                    <input
                      type="number"
                      value={newCurrentNumber}
                      onChange={(e) => setNewCurrentNumber(e.target.value)}
                      className="w-full rounded-lg border border-gray-300 px-3 md:px-4 py-2 text-sm md:text-base text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                      placeholder="輸入號碼"
                    />
                    <div className="flex gap-2">
                      <button
                        onClick={handleUpdateCurrentNumber}
                        disabled={loading}
                        className="flex-1 rounded-lg bg-blue-600 px-3 md:px-4 py-2 text-xs md:text-sm text-white font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        確認
                      </button>
                      <button
                        onClick={handleCancelEditCurrentNumber}
                        disabled={loading}
                        className="flex-1 rounded-lg bg-gray-200 px-3 md:px-4 py-2 text-xs md:text-sm text-gray-800 font-medium hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        取消
                      </button>
                    </div>
                  </div>
                ) : (
                  <p className="text-2xl md:text-3xl font-bold text-blue-600">{state.currentNumber}</p>
                )}
              </div>
              <div>
                <p className="text-xs md:text-sm text-gray-600">最後發出的票號</p>
                <p className="text-2xl md:text-3xl font-bold text-green-600">{state.lastTicket}</p>
              </div>
              <div>
                <p className="text-xs md:text-sm text-gray-600">候位數量</p>
                <p className="text-2xl md:text-3xl font-bold text-orange-600">{waitingCount}</p>
              </div>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs md:text-sm text-gray-600">下一號</p>
                  {!editingNextNumber && (
                    <button
                      onClick={() => {
                        setEditingNextNumber(true);
                        const nextNumber = state.nextNumber ?? (state.currentNumber + 1);
                        setNewNextNumber(String(nextNumber));
                      }}
                      className="text-xs md:text-sm text-blue-600 hover:text-blue-800 underline"
                    >
                      編輯
                    </button>
                  )}
                </div>
                {editingNextNumber ? (
                  <div className="space-y-2">
                    <input
                      type="number"
                      value={newNextNumber}
                      onChange={(e) => setNewNextNumber(e.target.value)}
                      className="w-full rounded-lg border border-gray-300 px-3 md:px-4 py-2 text-sm md:text-base text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                      placeholder="輸入下一號"
                    />
                    <div className="flex gap-2">
                      <button
                        onClick={handleUpdateNextNumber}
                        disabled={loading}
                        className="flex-1 rounded-lg bg-blue-600 px-3 md:px-4 py-2 text-xs md:text-sm text-white font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        確認
                      </button>
                      <button
                        onClick={handleCancelEditNextNumber}
                        disabled={loading}
                        className="flex-1 rounded-lg bg-gray-200 px-3 md:px-4 py-2 text-xs md:text-sm text-gray-800 font-medium hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        取消
                      </button>
                    </div>
                  </div>
                ) : (
                  <p className="text-2xl md:text-3xl font-bold text-purple-600">
                    {state.nextNumber ?? (state.currentNumber + 1)}
                  </p>
                )}
              </div>
            </div>
          </div>

          <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
            <h2 className="mb-3 md:mb-4 text-lg md:text-xl font-semibold text-gray-800">操作</h2>
            <div className="space-y-3 md:space-y-4">
              <a
                href="/ticket"
                className="block w-full text-center rounded-lg bg-blue-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-blue-700 transition-colors"
              >
                前往抽號頁面
              </a>
              <button
                onClick={handleNext}
                disabled={loading || (state.nextNumber ?? (state.currentNumber + 1)) > state.lastTicket}
                className="w-full rounded-lg bg-purple-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                下一號
              </button>
              <button
                onClick={handleExportExcel}
                disabled={loading}
                className="w-full rounded-lg bg-green-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                匯出 Excel
              </button>
              <button
                onClick={handleSuperAdminClick}
                disabled={loading}
                className="w-full rounded-lg bg-orange-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                超級管理員
              </button>
            </div>
          </div>
        </div>

        {/* 票券列表 */}
        <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
          <h2 className="mb-4 md:mb-6 text-xl md:text-2xl font-semibold text-gray-800">號碼列表</h2>
          {sortedTickets.length === 0 ? (
            <div className="text-center py-8 md:py-12 text-sm md:text-base text-gray-500">
              目前沒有任何票券
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6">
              {sortedTickets.map((ticket) => (
                <div
                  key={ticket.ticketNumber}
                  className={`rounded-lg border-2 p-4 md:p-5 transition-all ${
                    isCurrentNumber(ticket.ticketNumber)
                      ? "border-blue-500 bg-blue-50"
                      : isCalled(ticket.ticketNumber)
                      ? "border-gray-300 bg-gray-50"
                      : "border-gray-200 bg-white"
                  }`}
                >
                  {editingTicket === ticket.ticketNumber ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between mb-3">
                        <div
                          className={`text-xl md:text-2xl font-bold ${
                            isCurrentNumber(ticket.ticketNumber)
                              ? "text-blue-600"
                              : isCalled(ticket.ticketNumber)
                              ? "text-gray-500"
                              : "text-gray-900"
                          }`}
                        >
                          #{ticket.ticketNumber}
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs md:text-sm font-medium text-gray-700 mb-2">
                          處理進度
                        </label>
                        <select
                          value={editStatus}
                          onChange={(e) => setEditStatus(e.target.value as TicketStatus)}
                          className="w-full rounded-lg border border-gray-300 px-3 md:px-4 py-2 text-sm md:text-base text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                        >
                          <option value="pending">等待中</option>
                          <option value="processing">處理中</option>
                          <option value="replied">已回覆</option>
                          <option value="completed">已完成</option>
                          <option value="cancelled">已取消</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs md:text-sm font-medium text-gray-700 mb-2">
                          備註
                        </label>
                        <textarea
                          value={editNote}
                          onChange={(e) => setEditNote(e.target.value)}
                          rows={3}
                          className="w-full rounded-lg border border-gray-300 px-3 md:px-4 py-2 text-sm md:text-base text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none resize-none"
                          placeholder="輸入備註內容..."
                        />
                      </div>
                      <div>
                        <label className="block text-xs md:text-sm font-medium text-gray-700 mb-2">
                          PM
                        </label>
                        <input
                          type="text"
                          value={editAssignee}
                          onChange={(e) => setEditAssignee(e.target.value)}
                          className="w-full rounded-lg border border-gray-300 px-3 md:px-4 py-2 text-sm md:text-base text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                          placeholder="輸入PM姓名"
                        />
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            saveEdit(ticket.ticketNumber);
                          }}
                          disabled={loading}
                          className="flex-1 rounded-lg bg-blue-600 px-3 md:px-4 py-2 text-sm md:text-base text-white font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          儲存
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            cancelEdit();
                          }}
                          disabled={loading}
                          className="flex-1 rounded-lg bg-gray-200 px-3 md:px-4 py-2 text-sm md:text-base text-gray-800 font-medium hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          取消
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div className="flex items-start justify-between mb-3">
                        <div 
                          className="flex-1 cursor-pointer"
                          onClick={() => setViewingTicket(ticket)}
                        >
                          <div
                            className={`text-xl md:text-2xl font-bold mb-2 ${
                              isCurrentNumber(ticket.ticketNumber)
                                ? "text-blue-600"
                                : isCalled(ticket.ticketNumber)
                                ? "text-gray-500"
                                : "text-gray-900"
                            }`}
                          >
                            #{ticket.ticketNumber}
                          </div>
                          {ticket.applicant && (
                            <div className="text-sm md:text-base text-gray-700 mb-2">
                              申請人：{ticket.applicant}
                            </div>
                          )}
                          {ticket.assignee && (
                            <div className="text-sm md:text-base text-gray-700 mb-2">
                              PM：{ticket.assignee}
                            </div>
                          )}
                          <div className="flex flex-wrap items-center gap-2">
                            {isCurrentNumber(ticket.ticketNumber) && (
                              <span className="px-2 py-1 rounded-full bg-blue-600 text-white text-xs font-medium whitespace-nowrap">
                                目前號碼
                              </span>
                            )}
                            <span
                              className={`px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap ${statusColors[ticket.status]}`}
                            >
                              {statusLabels[ticket.status]}
                            </span>
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setViewingTicket(ticket);
                            }}
                            className="rounded-lg bg-green-600 px-3 md:px-4 py-1.5 md:py-2 text-xs md:text-sm text-white font-medium hover:bg-green-700 transition-colors whitespace-nowrap"
                          >
                            查看
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              startEdit(ticket);
                            }}
                            className="rounded-lg bg-blue-600 px-3 md:px-4 py-1.5 md:py-2 text-xs md:text-sm text-white font-medium hover:bg-blue-700 transition-colors whitespace-nowrap"
                          >
                            編輯
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDelete(ticket.ticketNumber);
                            }}
                            disabled={loading}
                            className="rounded-lg bg-red-600 px-3 md:px-4 py-1.5 md:py-2 text-xs md:text-sm text-white font-medium hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
                          >
                            刪除
                          </button>
                        </div>
                      </div>

                      {ticket.note && (
                        <div className="mt-3 p-2 md:p-3 bg-gray-50 rounded-lg border-l-4 border-blue-500">
                          <p className="text-xs md:text-sm font-medium text-gray-700 mb-1">備註</p>
                          <p className="text-sm md:text-base text-gray-900 break-words whitespace-pre-wrap line-clamp-2">
                            {ticket.note}
                          </p>
                        </div>
                      )}
                    {ticket.assignee && (
                      <div className="mt-3 p-2 md:p-3 bg-purple-50 rounded-lg border-l-4 border-purple-500">
                        <p className="text-xs md:text-sm font-medium text-gray-700 mb-1">PM</p>
                        <p className="text-sm md:text-base text-gray-900 break-words">
                          {ticket.assignee}
                        </p>
                      </div>
                    )}
                    {ticket.status === "replied" && ticket.replyDate && (
                      <div className="mt-2 text-xs md:text-sm text-gray-700">
                        已回覆累積天數：{
                          calculateTaiwanDayDiff(ticket.replyDate)
                        } 天
                      </div>
                    )}
                    {ticket.fcst && (
                      <div className="mt-3 p-2 md:p-3 bg-yellow-50 rounded-lg border-l-4 border-yellow-500">
                        <p className="text-xs md:text-sm font-medium text-gray-700 mb-1">FCST</p>
                        <p className="text-sm md:text-base text-gray-900 break-words">
                          {ticket.fcst}
                        </p>
                      </div>
                    )}
                    {ticket.massProductionDate && (
                      <div className="mt-3 p-2 md:p-3 bg-green-50 rounded-lg border-l-4 border-green-500">
                        <p className="text-xs md:text-sm font-medium text-gray-700 mb-1">預計量產日</p>
                        <p className="text-sm md:text-base text-gray-900 break-words">
                          {ticket.massProductionDate}
                        </p>
                      </div>
                    )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="mt-4 md:mt-6 text-center">
          <a
            href="/"
            className="text-sm md:text-base text-blue-600 hover:text-blue-800 underline"
          >
            返回首頁
          </a>
        </div>
      </div>

      {/* 彈窗：顯示完整票券資訊 */}
      {viewingTicket && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
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
                  <div className={`inline-block px-4 md:px-5 py-2 md:py-2.5 rounded-full text-sm md:text-base font-semibold ${statusColors[viewingTicket.status]}`}>
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
                  onClick={() => {
                    setViewingTicket(null);
                    startEdit(viewingTicket);
                  }}
                  className="flex-1 rounded-lg bg-blue-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium hover:bg-blue-700 transition-colors"
                >
                  編輯狀態與備註
                </button>
                <button
                  onClick={() => setViewingTicket(null)}
                  className="flex-1 rounded-lg bg-gray-200 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-gray-800 font-medium hover:bg-gray-300 transition-colors"
                >
                  關閉
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 超級管理員彈窗 */}
      {showSuperAdminModal && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={handleSuperAdminCancel}
        >
          <div
            className="bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 md:p-8">
              {!isSuperAdminAuthenticated ? (
                <>
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl md:text-3xl font-bold text-gray-900">
                      超級管理員
                    </h2>
                    <button
                      onClick={handleSuperAdminCancel}
                      className="text-gray-400 hover:text-gray-600 transition-colors"
                    >
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <p className="text-sm md:text-base text-gray-600 mb-6 text-center">
                    請輸入密碼以進入超級管理員功能
                  </p>
                  <form onSubmit={handleSuperAdminPasswordSubmit} className="space-y-4">
                    <div>
                      <label
                        htmlFor="superAdminPassword"
                        className="block text-sm font-medium text-gray-700 mb-2"
                      >
                        密碼
                      </label>
                      <input
                        type="password"
                        id="superAdminPassword"
                        value={superAdminPassword}
                        onChange={(e) => {
                          setSuperAdminPassword(e.target.value);
                          setSuperAdminPasswordError("");
                        }}
                        className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500 focus:outline-none transition-colors"
                        placeholder="請輸入密碼"
                        autoFocus
                        required
                      />
                      {superAdminPasswordError && (
                        <p className="mt-2 text-sm text-red-600">{superAdminPasswordError}</p>
                      )}
                    </div>
                    <div className="flex gap-3 pt-4">
                      <button
                        type="button"
                        onClick={handleSuperAdminCancel}
                        className="flex-1 rounded-lg bg-gray-200 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-gray-800 font-medium hover:bg-gray-300 transition-colors"
                      >
                        取消
                      </button>
                      <button
                        type="submit"
                        className="flex-1 rounded-lg bg-orange-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-orange-700 transition-colors"
                      >
                        確認
                      </button>
                    </div>
                  </form>
                </>
              ) : (
                <>
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl md:text-3xl font-bold text-gray-900">
                      超級管理員功能
                    </h2>
                    <button
                      onClick={handleSuperAdminCancel}
                      className="text-gray-400 hover:text-gray-600 transition-colors"
                    >
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <div className="space-y-3 md:space-y-4">
                    <button
                      onClick={handleResetClick}
                      disabled={loading}
                      className="w-full rounded-lg bg-red-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      重置系統
                    </button>
                    <button
                      onClick={handleImportExcel}
                      disabled={loading}
                      className="w-full rounded-lg bg-indigo-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      匯入 Excel
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
