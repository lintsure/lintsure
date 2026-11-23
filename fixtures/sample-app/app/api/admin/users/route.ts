import { db } from "../../../../src/db";

export async function DELETE(req: Request) {
  const target = new URL(req.url).searchParams.get("id");
  await db.users.remove(target);
  return Response.json({ ok: true });
}
