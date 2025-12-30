import { redis } from "./redis";

export type UserRole = "pm" | "super";

export interface UserRecord {
  username: string;
  password: string;
  role: UserRole;
}

const USERS_SET_KEY = "users:list";
const USERS_INITIALIZED_KEY = "users:initialized";
const DEFAULT_PM_USER = {
  username: "pmadmin",
  password: process.env.DEFAULT_PM_PASSWORD || "Bailey",
  role: "pm" as UserRole,
};
const DEFAULT_SUPER_USER = {
  username: "superadmin",
  password: process.env.DEFAULT_SUPER_PASSWORD || "Eunice",
  role: "super" as UserRole,
};

async function saveUser(user: UserRecord) {
  await redis.hset(`user:${user.username}`, {
    password: user.password,
    role: user.role,
  });
  await redis.sadd(USERS_SET_KEY, user.username);
  return { username: user.username, role: user.role };
}

export async function ensureDefaultUsers() {
  const initialized = await redis.get<string>(USERS_INITIALIZED_KEY);
  if (initialized === "true") return;

  await saveUser(DEFAULT_PM_USER);
  await saveUser(DEFAULT_SUPER_USER);
  await redis.set(USERS_INITIALIZED_KEY, "true");
}

export async function listUsers() {
  await ensureDefaultUsers();
  const usernames = (await redis.smembers<string[]>(USERS_SET_KEY)) || [];
  const users = await Promise.all(
    usernames.map(async (username) => {
      const user = await redis.hgetall<{ password?: string; role?: UserRole }>(
        `user:${username}`
      );
      if (!user || !user.role) return null;
      return { username, role: user.role as UserRole };
    })
  );
  return users.filter((u): u is { username: string; role: UserRole } => Boolean(u));
}

export async function getUser(username: string) {
  await ensureDefaultUsers();
  const user = await redis.hgetall<{ password?: string; role?: UserRole }>(
    `user:${username}`
  );
  if (!user || !user.password || !user.role) return null;
  return {
    username,
    password: user.password,
    role: user.role as UserRole,
  };
}

export async function createOrUpdateUser(user: UserRecord) {
  await ensureDefaultUsers();
  return saveUser(user);
}

export async function verifyUser(username: string, password: string) {
  const user = await getUser(username);
  if (!user) return null;
  if (String(user.password) !== String(password)) return null;
  return { username: user.username, role: user.role };
}
