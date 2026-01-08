"use client";

import { useState, useEffect, useRef } from "react";

interface QueueState {
  currentNumber: number;
  lastTicket: number;
  nextNumber?: number;
  pm?: string;
}

interface PmState {
  pm: string;
  currentNumber: number;
  nextNumber: number;
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

interface LogPayload {
  action: string;
  detail?: string;
}

const PM_STORAGE_KEY = "pmAuth";

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
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [state, setState] = useState<QueueState>({ currentNumber: 0, lastTicket: 0, nextNumber: 1 });
  const [pmStates, setPmStates] = useState<Record<string, PmState>>({});
  const [tickets, setTickets] = useState<TicketInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [editingTicket, setEditingTicket] = useState<number | null>(null);
  const [editStatus, setEditStatus] = useState<TicketStatus>("pending");
  const [editNote, setEditNote] = useState<string>("");
  const [editAssignee, setEditAssignee] = useState<string>("");
  const [viewingTicket, setViewingTicket] = useState<TicketInfo | null>(null);
  const [editingPmStates, setEditingPmStates] = useState<Record<string, { current?: string; next?: string }>>({});
  const editingTicketRef = useRef<number | null>(null);
  const [pmUsers, setPmUsers] = useState<string[]>([]);
  const [pmFilter, setPmFilter] = useState<string>("");

  const logEvent = async (payload: LogPayload) => {
    if (!username) return;
    try {
      await fetch("/api/logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          role: "pm",
          action: payload.action,
          detail: payload.detail,
        }),
      });
    } catch (error) {
      console.error("logEvent failed", error);
    }
  };

  // Check if already authenticated (from sessionStorage) and register auto-logout on leave
  useEffect(() => {
    const cached = sessionStorage.getItem(PM_STORAGE_KEY);
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (parsed?.username) {
          setUsername(parsed.username);
          setIsAuthenticated(true);
        }
      } catch (error) {
        console.error("Failed to parse cached pm auth", error);
      }
    }

    const clearAuth = () => {
      sessionStorage.removeItem(PM_STORAGE_KEY);
    };
    // 僅在分頁關閉或重整時清除；站內路由切換不會觸發
    window.addEventListener("beforeunload", clearAuth);
    return () => {
      window.removeEventListener("beforeunload", clearAuth);
    };
  }, []);

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError("");
    setAuthLoading(true);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setPasswordError(data?.error || "登入失敗，請重試");
        return;
      }

      if (data.role !== "pm" && data.role !== "super") {
        setPasswordError("無效的角色，請聯繫管理員");
        return;
      }

      setIsAuthenticated(true);
      sessionStorage.setItem(PM_STORAGE_KEY, JSON.stringify({ username: data.username }));
      logEvent({ action: "login" });
    } catch (error) {
      console.error("Login failed", error);
      setPasswordError("登入失敗，請重試");
    } finally {
      setAuthLoading(false);
      setPassword("");
    }
  };

  const handleLogout = () => {
    logEvent({ action: "logout" });
    setIsAuthenticated(false);
    sessionStorage.removeItem(PM_STORAGE_KEY);
    setUsername("");
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

  const fetchAllPmStates = async () => {
    try {
      const allPms = ["unassigned", ...pmUsers];
      const states: Record<string, PmState> = {};
      
      for (const pm of allPms) {
        try {
          const res = await fetch(`/api/state?pm=${encodeURIComponent(pm)}`, { cache: "no-store" });
          if (res.ok) {
            const data = await res.json();
            states[pm] = {
              pm,
              currentNumber: data.currentNumber ?? 0,
              nextNumber: data.nextNumber ?? (data.currentNumber ?? 0) + 1,
            };
          }
        } catch (error) {
          console.error(`Failed to fetch state for ${pm}:`, error);
        }
      }
      
      setPmStates(states);
    } catch (error) {
      console.error("Failed to fetch PM states:", error);
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

  const fetchPmUsers = async () => {
    try {
      const res = await fetch("/api/users/pm-list");
      if (res.ok) {
        const data = await res.json();
        const usernames = (data.users || []).map((u: { username: string; role: string }) => u.username);
        setPmUsers(usernames);
      }
    } catch (error) {
      console.error("Failed to fetch PM users:", error);
    }
  };

  useEffect(() => {
    if (!isAuthenticated) return;
    fetchState();
    fetchTickets();
    fetchPmUsers();
  }, [isAuthenticated]);

  useEffect(() => {
    if (pmUsers.length > 0) {
      fetchAllPmStates();
    }
  }, [pmUsers]);

  const handleNext = async (pm?: string) => {
    setLoading(true);
    try {
      await fetch("/api/next", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pm }),
      });
      await fetchState();
      await fetchAllPmStates();
      await fetchTickets();
    } catch (error) {
      console.error("Failed to call next:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePmState = async (pm: string, field: "current" | "next", value: string) => {
    const numberValue = Number(value);
    if (isNaN(numberValue)) {
      alert("請輸入有效的數字");
      return;
    }

    setLoading(true);
    try {
      const body: any = { pm };
      if (field === "current") {
        body.currentNumber = numberValue;
      } else {
        body.nextNumber = numberValue;
      }

      const res = await fetch("/api/state", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "更新失敗");
      }

      // Clear editing state
      setEditingPmStates((prev) => {
        const next = { ...prev };
        if (next[pm]) {
          delete next[pm][field];
          if (Object.keys(next[pm]).length === 0) {
            delete next[pm];
          }
        }
        return next;
      });

      await fetchAllPmStates();
      await fetchTickets();
    } catch (error) {
      console.error("Failed to update PM state:", error);
      alert(error instanceof Error ? error.message : "更新失敗，請重試");
    } finally {
      setLoading(false);
    }
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
        // 先嘗試 RFC 5987 的 filename*
        const matchUtf8 = contentDisposition.match(/filename\*\=UTF-8''([^;]+)/i);
        if (matchUtf8?.[1]) {
          fileName = decodeURIComponent(matchUtf8[1]);
        } else {
          const fileNameMatch = contentDisposition.match(/filename="?([^\";]+)"?/i);
          if (fileNameMatch?.[1]) {
            fileName = decodeURIComponent(fileNameMatch[1]);
          }
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

      logEvent({
        action: "ticket:update",
        detail: `#${ticketNumber} status=${editStatus} assignee=${editAssignee || ""}`,
      });
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

      logEvent({
        action: "ticket:delete",
        detail: `#${ticketNumber}`,
      });
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
            <h1 className="text-2xl md:text-3xl font-bold text-gray-900 mb-6 text-center">PM 管理平台登入</h1>
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
                  使用者帳號
                </label>
                <input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    setPasswordError("");
                  }}
                  className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
                  placeholder="請輸入帳號"
                  autoFocus
                />
              </div>
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
                />
              </div>
              {passwordError && (
                <div className="rounded-lg bg-red-50 border border-red-200 p-3">
                  <p className="text-sm text-red-600">{passwordError}</p>
                </div>
              )}
              <button
                type="submit"
                disabled={authLoading}
                className="w-full rounded-lg bg-blue-600 px-6 py-3 text-white font-medium shadow-md hover:bg-blue-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {authLoading ? "登入中..." : "登入"}
              </button>
            </form>
            <div className="mt-6 text-center space-y-2">
              <a
                href="/"
                className="text-sm text-blue-600 hover:text-blue-800 underline block"
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
  
  // Filter tickets by PM
  const filteredTickets = pmFilter
    ? tickets.filter((t) => {
        if (pmFilter === "unassigned") {
          return !t.assignee || t.assignee === "";
        }
        return t.assignee === pmFilter;
      })
    : tickets;

  // Sort tickets in descending order (newest first)
  const sortedTickets = [...filteredTickets].sort((a, b) => b.ticketNumber - a.ticketNumber);

  // Get unassigned tickets
  const unassignedTickets = tickets.filter((t) => !t.assignee || t.assignee === "");

  // Helper to check if ticket is current for a specific PM
  const isCurrentNumberForPm = (ticketNumber: number, pm?: string) => {
    if (!pm) return false;
    const pmState = pmStates[pm];
    if (!pmState) return false;
    return ticketNumber === pmState.currentNumber;
  };

  const isCalledForPm = (ticketNumber: number, pm?: string) => {
    if (!pm) return false;
    const pmState = pmStates[pm];
    if (!pmState) return false;
    return ticketNumber <= pmState.currentNumber;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 p-3 md:p-8">
      <div className="mx-auto max-w-7xl">
        <div className="mb-6 md:mb-8 text-center">
          <div className="flex items-center justify-between mb-2">
            <div className="flex-1"></div>
            <h1 className="text-2xl md:text-4xl font-bold text-gray-900 flex-1">PM 管理平台</h1>
            <div className="flex-1 flex justify-end">
              <button
                onClick={handleLogout}
                className="rounded-lg bg-gray-600 px-4 py-2 text-sm md:text-base text-white font-medium hover:bg-gray-700 transition-colors"
              >
                登出
              </button>
            </div>
          </div>
          <p className="text-sm md:text-base text-gray-600">
            叫號系統管理 {username ? `｜ 歡迎，${username}` : ""}
          </p>
        </div>

        {/* PM 狀態列表 */}
        <div className="mb-6 md:mb-8">
          <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-4">各 PM 狀態</h2>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {/* 未指派 PM */}
            <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg border-2 border-gray-300">
              <h3 className="text-lg font-semibold text-gray-800 mb-4">尚未指派 PM</h3>
              <div className="flex flex-col items-center justify-center py-4">
                <p className="text-5xl md:text-6xl lg:text-7xl font-bold text-blue-600 mb-2">
                  {unassignedTickets.length}
                </p>
                <p className="text-sm md:text-base text-gray-600">號碼總數</p>
              </div>
            </div>

            {/* 各 PM 狀態 */}
            {pmUsers.map((pm) => {
              const pmState = pmStates[pm];
              const pmTickets = tickets.filter((t) => t.assignee === pm);
              return (
                <div key={pm} className="rounded-xl bg-white p-4 md:p-6 shadow-lg border-2 border-blue-300">
                  <h3 className="text-lg font-semibold text-gray-800 mb-3">{pm}</h3>
                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-xs text-gray-600">目前號碼</p>
                        {!editingPmStates[pm]?.current && (
                          <button
                            onClick={() => {
                              setEditingPmStates((prev) => ({
                                ...prev,
                                [pm]: { ...prev[pm], current: String(pmState?.currentNumber ?? 0) },
                              }));
                            }}
                            className="text-xs text-blue-600 hover:text-blue-800 underline"
                          >
                            編輯
                          </button>
                        )}
                      </div>
                      {editingPmStates[pm]?.current !== undefined ? (
                        <div className="space-y-2">
                          <input
                            type="number"
                            value={editingPmStates[pm].current}
                            onChange={(e) => {
                              setEditingPmStates((prev) => ({
                                ...prev,
                                [pm]: { ...prev[pm], current: e.target.value },
                              }));
                            }}
                            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                          />
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleUpdatePmState(pm, "current", editingPmStates[pm].current!)}
                              disabled={loading}
                              className="flex-1 rounded-lg bg-blue-600 px-3 py-1.5 text-xs text-white font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
                            >
                              確認
                            </button>
                            <button
                              onClick={() => {
                                setEditingPmStates((prev) => {
                                  const next = { ...prev };
                                  if (next[pm]) {
                                    delete next[pm].current;
                                    if (Object.keys(next[pm]).length === 0) delete next[pm];
                                  }
                                  return next;
                                });
                              }}
                              className="flex-1 rounded-lg bg-gray-200 px-3 py-1.5 text-xs text-gray-800 font-medium hover:bg-gray-300 transition-colors"
                            >
                              取消
                            </button>
                          </div>
                        </div>
                      ) : (
                        <p className="text-xl font-bold text-blue-600">{pmState?.currentNumber ?? 0}</p>
                      )}
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-xs text-gray-600">下一號</p>
                        {!editingPmStates[pm]?.next && (
                          <button
                            onClick={() => {
                              setEditingPmStates((prev) => ({
                                ...prev,
                                [pm]: { ...prev[pm], next: String(pmState?.nextNumber ?? 1) },
                              }));
                            }}
                            className="text-xs text-blue-600 hover:text-blue-800 underline"
                          >
                            編輯
                          </button>
                        )}
                      </div>
                      {editingPmStates[pm]?.next !== undefined ? (
                        <div className="space-y-2">
                          <input
                            type="number"
                            value={editingPmStates[pm].next}
                            onChange={(e) => {
                              setEditingPmStates((prev) => ({
                                ...prev,
                                [pm]: { ...prev[pm], next: e.target.value },
                              }));
                            }}
                            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                          />
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleUpdatePmState(pm, "next", editingPmStates[pm].next!)}
                              disabled={loading}
                              className="flex-1 rounded-lg bg-blue-600 px-3 py-1.5 text-xs text-white font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
                            >
                              確認
                            </button>
                            <button
                              onClick={() => {
                                setEditingPmStates((prev) => {
                                  const next = { ...prev };
                                  if (next[pm]) {
                                    delete next[pm].next;
                                    if (Object.keys(next[pm]).length === 0) delete next[pm];
                                  }
                                  return next;
                                });
                              }}
                              className="flex-1 rounded-lg bg-gray-200 px-3 py-1.5 text-xs text-gray-800 font-medium hover:bg-gray-300 transition-colors"
                            >
                              取消
                            </button>
                          </div>
                        </div>
                      ) : (
                        <p className="text-xl font-bold text-purple-600">{pmState?.nextNumber ?? 1}</p>
                      )}
                    </div>
                    <button
                      onClick={() => handleNext(pm)}
                      disabled={loading || (pmState?.nextNumber ?? 1) > state.lastTicket}
                      className="w-full rounded-lg bg-purple-600 px-4 py-2 text-sm text-white font-medium hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      下一號
                    </button>
                    <p className="text-xs text-gray-500">號碼數：{pmTickets.length}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* 狀態和操作卡片 */}
        <div className="grid gap-4 md:gap-6 md:grid-cols-2 mb-6 md:mb-8">
          <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
            <h2 className="mb-3 md:mb-4 text-lg md:text-xl font-semibold text-gray-800">系統狀態</h2>
            <div className="space-y-3 md:space-y-4">
              <div>
                <p className="text-xs md:text-sm text-gray-600">最後發出的票號</p>
                <p className="text-2xl md:text-3xl font-bold text-green-600">{state.lastTicket}</p>
              </div>
              <div>
                <p className="text-xs md:text-sm text-gray-600">候位數量</p>
                <p className="text-2xl md:text-3xl font-bold text-orange-600">{waitingCount}</p>
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
                onClick={handleExportExcel}
                disabled={loading}
                className="w-full rounded-lg bg-green-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                匯出 Excel
              </button>
            </div>
          </div>
        </div>

        {/* 票券列表 */}
        <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-4 md:mb-6 gap-3">
            <h2 className="text-xl md:text-2xl font-semibold text-gray-800">號碼列表</h2>
            <select
              value={pmFilter}
              onChange={(e) => setPmFilter(e.target.value)}
              className="rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
            >
              <option value="">全部 PM</option>
              <option value="unassigned">尚未指派 PM</option>
              {pmUsers.map((pm) => (
                <option key={pm} value={pm}>
                  {pm}
                </option>
              ))}
            </select>
          </div>
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
                    isCurrentNumberForPm(ticket.ticketNumber, ticket.assignee || (pmFilter === "unassigned" ? "unassigned" : undefined))
                      ? "border-blue-500 bg-blue-50"
                      : isCalledForPm(ticket.ticketNumber, ticket.assignee || (pmFilter === "unassigned" ? "unassigned" : undefined))
                      ? "border-gray-300 bg-gray-50"
                      : "border-gray-200 bg-white"
                  }`}
                >
                  {editingTicket === ticket.ticketNumber ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between mb-3">
                        <div
                          className={`text-xl md:text-2xl font-bold ${
                            isCurrentNumberForPm(ticket.ticketNumber, ticket.assignee || (pmFilter === "unassigned" ? "unassigned" : undefined))
                              ? "text-blue-600"
                              : isCalledForPm(ticket.ticketNumber, ticket.assignee || (pmFilter === "unassigned" ? "unassigned" : undefined))
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
                        <select
                          value={editAssignee}
                          onChange={(e) => setEditAssignee(e.target.value)}
                          className="w-full rounded-lg border border-gray-300 px-3 md:px-4 py-2 text-sm md:text-base text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                        >
                          <option value="">請選擇 PM</option>
                          {pmUsers.map((pm) => (
                            <option key={pm} value={pm}>
                              {pm}
                            </option>
                          ))}
                        </select>
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
                              isCurrentNumberForPm(ticket.ticketNumber, ticket.assignee || (pmFilter === "unassigned" ? "unassigned" : undefined))
                                ? "text-blue-600"
                                : isCalledForPm(ticket.ticketNumber, ticket.assignee || (pmFilter === "unassigned" ? "unassigned" : undefined))
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
                            {isCurrentNumberForPm(ticket.ticketNumber, ticket.assignee || (pmFilter === "unassigned" ? "unassigned" : undefined)) && (
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

    </div>
  );
}
