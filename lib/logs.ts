import { redis } from "./redis";

export interface LogEntry {
  ts: string;
  username: string;
  role: string;
  action: string;
  detail?: string;
}

// 使用單一 sorted set 儲存，score 為 timestamp(ms)，並按 60 天清除
const LOG_KEY = "logs:z";
const LOG_RETENTION_MS = 60 * 24 * 60 * 60 * 1000; // 60 days

export async function addLog(entry: LogEntry) {
  const now = Date.now();
  const payload = JSON.stringify(entry);
  await redis.zadd(LOG_KEY, { score: now, member: payload });
  // 清理 60 天以前的紀錄
  await redis.zremrangebyscore(LOG_KEY, 0, now - LOG_RETENTION_MS);
}

export async function getRecentLogs(limit = 500): Promise<LogEntry[]> {
  const size = Math.max(1, Math.min(limit, 2000));
  const raw = await redis.zrange(LOG_KEY, 0, size - 1, { rev: true });
  if (!raw || raw.length === 0) return [];
  return raw
    .map((item) => {
      if (typeof item === "string") {
        try {
          return JSON.parse(item) as LogEntry;
        } catch {
          return null;
        }
      }
      if (typeof item === "object" && item !== null) {
        return item as LogEntry;
      }
      return null;
    })
    .filter(Boolean) as LogEntry[];
}
