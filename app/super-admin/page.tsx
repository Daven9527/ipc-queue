"use client";

import { useEffect, useState } from "react";

type UserRole = "pm" | "super";

interface UserItem {
  username: string;
  role: UserRole;
}

interface LogItem {
  ts: string;
  username: string;
  role: string;
  action: string;
  detail?: string;
}

interface AuthState {
  username: string;
  token: string;
}

const SUPER_STORAGE_KEY = "superAuth";

export default function SuperAdminPage() {
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);

  const [users, setUsers] = useState<UserItem[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [systemLoading, setSystemLoading] = useState(false);
  const [importLoading, setImportLoading] = useState(false);
  const [deletingUser, setDeletingUser] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState<string>("");
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [showLogsModal, setShowLogsModal] = useState(false);

  const [formUsername, setFormUsername] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [formRole, setFormRole] = useState<UserRole>("pm");
  const [formError, setFormError] = useState("");
  const [editingUser, setEditingUser] = useState<string | null>(null);

  const authHeader: HeadersInit | undefined = auth
    ? { Authorization: `Basic ${auth.token}` }
    : undefined;

  const logEvent = async (action: string, detail?: string) => {
    if (!auth?.username) return;
    try {
      await fetch("/api/logs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: auth.username,
          role: "super",
          action,
          detail,
        }),
      });
    } catch (error) {
      console.error("logEvent super failed", error);
    }
  };

  useEffect(() => {
    const cached = sessionStorage.getItem(SUPER_STORAGE_KEY);
    if (cached) {
      try {
        const parsed = JSON.parse(cached) as AuthState;
        if (parsed?.username && parsed?.token) {
          setAuth(parsed);
        }
      } catch (error) {
        console.error("Failed to parse super auth cache", error);
      }
    }

    const clearAuth = () => {
      sessionStorage.removeItem(SUPER_STORAGE_KEY);
    };
    // 僅在分頁關閉或重整時清除；站內路由切換不會觸發
    window.addEventListener("beforeunload", clearAuth);
    return () => {
      window.removeEventListener("beforeunload", clearAuth);
    };
  }, []);

  useEffect(() => {
    if (!auth) return;
    fetchUsers();
  }, [auth]);

  const fetchUsers = async () => {
    if (!auth) return;
    setUsersLoading(true);
    try {
      const res = await fetch("/api/users", {
        headers: authHeader,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        console.error("Failed to fetch users", data);
        return;
      }
      setUsers(data.users || []);
    } catch (error) {
      console.error("Failed to fetch users", error);
    } finally {
      setUsersLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    setLoginLoading(true);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUsername, password: loginPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setLoginError(data?.error || "登入失敗，請重試");
        return;
      }
      if (data.role !== "super") {
        setLoginError("此帳號非管理員角色");
        return;
      }

      const token = btoa(`${loginUsername}:${loginPassword}`);
      const newAuth = { username: data.username, token };
      setAuth(newAuth);
      sessionStorage.setItem(SUPER_STORAGE_KEY, JSON.stringify(newAuth));
      logEvent("login");
      setLoginPassword("");
    } catch (error) {
      console.error("Super admin login failed", error);
      setLoginError("登入失敗，請重試");
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = () => {
    logEvent("logout");
    setAuth(null);
    sessionStorage.removeItem(SUPER_STORAGE_KEY);
    setUsers([]);
  };

  const handleReset = async () => {
    if (!auth) return;
    if (!confirm("確定要重置系統嗎？此操作將清除所有號碼和資料，且無法復原。")) {
      return;
    }
    setSystemLoading(true);
    try {
      const res = await fetch("/api/reset", {
        method: "POST",
        headers: authHeader,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data?.error || "重置失敗，請重試");
        return;
      }
      alert("系統已重置");
    } catch (error) {
      console.error("Failed to reset", error);
      alert("重置失敗，請重試");
    } finally {
      setSystemLoading(false);
    }
  };

  const handleImport = async () => {
    if (!auth) return;
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".xlsx,.xls";
    input.onchange = async (event) => {
      const file = (event.target as HTMLInputElement).files?.[0];
      if (!file) return;
      setImportLoading(true);
      try {
        const formData = new FormData();
        formData.append("file", file);

        const res = await fetch("/api/import", {
          method: "POST",
          headers: authHeader,
          body: formData,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          alert(data?.error || "匯入失敗，請重試");
          return;
        }

        let message = `匯入完成！\n新增：${data.imported} 筆\n更新：${data.updated} 筆`;
        if (data.errors && data.errors.length > 0) {
          message += `\n\n錯誤：\n${data.errors.slice(0, 10).join("\n")}`;
          if (data.errors.length > 10) {
            message += `\n... 還有 ${data.errors.length - 10} 個錯誤`;
          }
        }
        alert(message);
      } catch (error) {
        console.error("Import failed", error);
        alert("匯入失敗，請重試");
      } finally {
        setImportLoading(false);
      }
    };
    input.click();
  };

  const handleFetchLogs = async () => {
    if (!auth) return;
    setLogsLoading(true);
    try {
      const res = await fetch("/api/logs", {
        headers: authHeader,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data?.error || "讀取日誌失敗");
        return;
      }
      setLogs(data.logs || []);
      setShowLogsModal(true);
    } catch (error) {
      console.error("fetch logs failed", error);
      alert("讀取日誌失敗");
    } finally {
      setLogsLoading(false);
    }
  };

  const handleExportLogs = async () => {
    if (!auth) return;
    try {
      const res = await fetch("/api/logs/export", {
        headers: authHeader,
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        alert(data?.error || "匯出失敗");
        return;
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "logs.csv";
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error("export logs failed", error);
      alert("匯出失敗");
    }
  };

  const handleEditUser = (user: UserItem) => {
    setEditingUser(user.username);
    setFormUsername(user.username);
    setFormRole(user.role);
    setFormPassword("");
    setFormError("");

    // 取得目前密碼（superadmin 不顯示）
    if (user.username === "superadmin") {
      setCurrentPassword("");
      return;
    }

    (async () => {
      try {
        const res = await fetch(`/api/users/${user.username}`, {
          headers: authHeader,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          console.error("Failed to fetch user password", data);
          setCurrentPassword("");
          return;
        }
        setCurrentPassword(data.password ?? "");
      } catch (error) {
        console.error("Failed to fetch user password", error);
        setCurrentPassword("");
      }
    })();
  };

  const handleCreateNew = () => {
    setEditingUser(null);
    setFormUsername("");
    setFormRole("pm");
    setFormPassword("");
    setFormError("");
    setCurrentPassword("");
  };

  const handleSaveUser = async () => {
    if (!auth) return;
    setFormError("");

    if (!formUsername) {
      setFormError("請輸入帳號");
      return;
    }
    if (!editingUser && !formPassword) {
      setFormError("請輸入密碼");
      return;
    }

    try {
    const payload: Record<string, string> = { role: formRole };
    const isSuperAdminEditing = editingUser === "superadmin";
    if (!isSuperAdminEditing && formPassword) {
      payload.password = formPassword;
    }

      const res = await fetch(
        editingUser ? `/api/users/${formUsername}` : "/api/users",
        {
          method: editingUser ? "PATCH" : "POST",
          headers: {
            ...(authHeader || {}),
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: formUsername,
            ...payload,
          }),
        }
      );
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setFormError(data?.error || "儲存失敗，請重試");
        return;
      }
      await fetchUsers();
      handleCreateNew();
    } catch (error) {
      console.error("Save user failed", error);
      setFormError("儲存失敗，請重試");
    }
  };

  const handleDeleteUser = async (user: UserItem) => {
    if (!auth) return;
    if (user.username === "superadmin") {
      alert("無法刪除 superadmin。");
      return;
    }
    if (user.username === auth.username) {
      alert("無法刪除自己。請使用另一管理員帳號操作。");
      return;
    }
    if (!confirm(`確定要刪除使用者 ${user.username} 嗎？`)) return;

    setDeletingUser(user.username);
    try {
      const res = await fetch(`/api/users/${user.username}`, {
        method: "DELETE",
        headers: authHeader,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data?.error || "刪除失敗");
        return;
      }
      await fetchUsers();
      if (editingUser === user.username) {
        handleCreateNew();
      }
    } catch (error) {
      console.error("Delete user failed", error);
      alert("刪除失敗，請重試");
    } finally {
      setDeletingUser(null);
    }
  };

  if (!auth) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="bg-white rounded-xl shadow-lg p-8">
            <h1 className="text-2xl md:text-3xl font-bold text-gray-900 mb-6 text-center">管理員控制台登入</h1>
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  帳號
                </label>
                <input
                  type="text"
                  value={loginUsername}
                  onChange={(e) => {
                    setLoginUsername(e.target.value);
                    setLoginError("");
                  }}
                  className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500 focus:outline-none transition-colors"
                  placeholder="請輸入帳號"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  密碼
                </label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => {
                    setLoginPassword(e.target.value);
                    setLoginError("");
                  }}
                  className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500 focus:outline-none transition-colors"
                  placeholder="請輸入密碼"
                />
              </div>
              {loginError && (
                <div className="rounded-lg bg-red-50 border border-red-200 p-3">
                  <p className="text-sm text-red-600">{loginError}</p>
                </div>
              )}
              <button
                type="submit"
                disabled={loginLoading}
                className="w-full rounded-lg bg-orange-600 px-6 py-3 text-white font-medium shadow-md hover:bg-orange-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loginLoading ? "登入中..." : "登入"}
              </button>
            </form>
            <div className="mt-6 text-center">
              <a href="/" className="text-sm text-blue-600 hover:text-blue-800 underline">
                返回首頁
              </a>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 p-3 md:p-8">
      <div className="mx-auto max-w-6xl">
        <div className="flex items-center justify-between mb-6 md:mb-8">
          <div>
            <h1 className="text-2xl md:text-4xl font-bold text-gray-900">管理員控制台</h1>
            <p className="text-sm md:text-base text-gray-600 mt-1">超級管理員專用 | {auth.username}</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleFetchLogs}
              disabled={logsLoading}
              className="rounded-lg bg-amber-600 px-4 py-2 text-sm md:text-base text-white font-medium hover:bg-amber-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {logsLoading ? "讀取日誌..." : "查看日誌"}
            </button>
            <a
              href="/admin"
              className="rounded-lg bg-gray-200 px-4 py-2 text-sm md:text-base text-gray-800 font-medium hover:bg-gray-300 transition-colors"
            >
              返回 PM 平台
            </a>
            <button
              onClick={handleLogout}
              className="rounded-lg bg-gray-600 px-4 py-2 text-sm md:text-base text-white font-medium hover:bg-gray-700 transition-colors"
            >
              登出
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6 mb-6">
          <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
            <h2 className="text-lg md:text-xl font-semibold text-gray-800 mb-4">系統管理</h2>
            <div className="space-y-3">
              <button
                onClick={handleReset}
                disabled={systemLoading}
                className="w-full rounded-lg bg-red-600 px-4 md:px-6 py-3 text-white font-medium shadow-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {systemLoading ? "重置中..." : "重置系統"}
              </button>
              <button
                onClick={handleImport}
                disabled={importLoading}
                className="w-full rounded-lg bg-indigo-600 px-4 md:px-6 py-3 text-white font-medium shadow-md hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {importLoading ? "匯入中..." : "匯入 Excel"}
              </button>
            </div>
          </div>

          <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
            <h2 className="text-lg md:text-xl font-semibold text-gray-800 mb-4">
              {editingUser ? "編輯使用者" : "新增使用者"}
            </h2>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">帳號</label>
                <input
                  type="text"
                  value={formUsername}
                  onChange={(e) => setFormUsername(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-gray-900 placeholder:text-gray-400 bg-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500 focus:outline-none transition-colors"
                  placeholder="輸入帳號"
                  disabled={!!editingUser}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">密碼{editingUser ? "（不變更可留空）" : ""}</label>
                <input
                  type="password"
                  value={formPassword}
                  onChange={(e) => setFormPassword(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-gray-900 placeholder:text-gray-400 bg-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500 focus:outline-none transition-colors"
                  placeholder={
                    editingUser
                      ? editingUser === "superadmin"
                        ? "superadmin 密碼不可變更"
                        : "如需變更請輸入新密碼"
                      : "請輸入密碼"
                  }
                  disabled={editingUser === "superadmin"}
                />
                {editingUser && editingUser !== "superadmin" && currentPassword && (
                  <p className="mt-1 text-xs text-gray-500">目前密碼：{currentPassword}</p>
                )}
                {editingUser === "superadmin" && (
                  <p className="mt-1 text-xs text-gray-500">superadmin 密碼不顯示</p>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">角色</label>
                <select
                  value={formRole}
                  onChange={(e) => setFormRole(e.target.value as UserRole)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-gray-900 bg-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500 focus:outline-none transition-colors"
                >
                  <option value="pm">PM</option>
                  <option value="super">管理員</option>
                </select>
              </div>
              {formError && (
                <div className="rounded-lg bg-red-50 border border-red-200 p-3">
                  <p className="text-sm text-red-600">{formError}</p>
                </div>
              )}
              <div className="flex gap-2">
                <button
                  onClick={handleSaveUser}
                  className="flex-1 rounded-lg bg-orange-600 px-4 py-2.5 text-white font-medium shadow-md hover:bg-orange-700 transition-colors"
                >
                  {editingUser ? "儲存變更" : "新增使用者"}
                </button>
                {editingUser && (
                  <button
                    onClick={handleCreateNew}
                    className="flex-1 rounded-lg bg-gray-200 px-4 py-2.5 text-gray-800 font-medium hover:bg-gray-300 transition-colors"
                  >
                    取消編輯
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-xl bg-white p-4 md:p-6 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg md:text-xl font-semibold text-gray-800">使用者列表</h2>
            {usersLoading && <span className="text-sm text-gray-500">讀取中...</span>}
          </div>
          {users.length === 0 ? (
            <div className="text-center text-gray-500 py-8">尚無使用者</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">帳號</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">角色</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {users.map((user) => (
                    <tr key={user.username}>
                      <td className="px-4 py-3 text-sm text-gray-900">{user.username}</td>
                      <td className="px-4 py-3 text-sm text-gray-700">{user.role === "super" ? "管理員" : "PM"}</td>
                      <td className="px-4 py-3 text-right space-x-2">
                        <button
                          onClick={() => handleEditUser(user)}
                          className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs text-white font-medium hover:bg-blue-700 transition-colors"
                        >
                          編輯
                        </button>
                        <button
                          onClick={() => handleDeleteUser(user)}
                          disabled={deletingUser === user.username || user.username === "superadmin"}
                          className="rounded-lg bg-red-600 px-3 py-1.5 text-xs text-white font-medium hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          {user.username === "superadmin"
                            ? "不可刪除"
                            : deletingUser === user.username
                            ? "刪除中..."
                            : "刪除"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {showLogsModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={() => setShowLogsModal(false)}>
          <div
            className="bg-white rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-4 md:p-6 border-b flex items-center justify-between">
              <div>
                <h3 className="text-lg md:text-xl font-semibold text-gray-900">活動日誌 (近 60 天)</h3>
                <p className="text-sm text-gray-500 mt-1">登入、重置、帳號新增/編輯/刪除等操作</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleExportLogs}
                  className="rounded-lg bg-green-600 px-3 py-1.5 text-sm text-white font-medium hover:bg-green-700 transition-colors"
                >
                  匯出 CSV
                </button>
                <button
                  onClick={() => setShowLogsModal(false)}
                  className="rounded-lg bg-gray-200 px-3 py-1.5 text-sm text-gray-800 font-medium hover:bg-gray-300 transition-colors"
                >
                  關閉
                </button>
              </div>
            </div>
            <div className="p-4 md:p-6 overflow-y-auto">
              {logs.length === 0 ? (
                <div className="text-center text-gray-500 py-8">暫無日誌</div>
              ) : (
                <div className="space-y-2">
                  {logs.map((log, idx) => (
                    <div key={idx} className="border rounded-lg p-3 md:p-4 bg-gray-50">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="text-sm text-gray-700">{new Date(log.ts).toLocaleString()}</div>
                        <div className="text-xs px-2 py-1 rounded bg-gray-200 text-gray-800">
                          {log.username} ({log.role})
                        </div>
                      </div>
                      <div className="mt-2 text-sm font-semibold text-gray-900">{log.action}</div>
                      {log.detail && <div className="mt-1 text-sm text-gray-700 break-words">{log.detail}</div>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
