import { logger } from "./logger";

export async function signup(user: { email: string; name: string }) {
  await save(user);
  logger.info(`signup ${user.email}`);
}
declare function save(u: unknown): Promise<void>;
