import { db } from "../../../../src/db";
import { getServerSession } from "../../../../src/session";

export async function DELETE(req: Request) {
  const session = await getServerSession();
  if (session?.user.role !== "admin") return new Response(null, { status: 403 });
  const target = new URL(req.url).searchParams.get("id");
  await db.users.remove(target);
  return Response.json({ ok: true });
}
