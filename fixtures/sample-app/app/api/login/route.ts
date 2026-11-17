import { checkPassword } from "../../../src/users";

export async function POST(req: Request) {
  const { email, password } = await req.json();
  return Response.json({ ok: await checkPassword(email, password) });
}
