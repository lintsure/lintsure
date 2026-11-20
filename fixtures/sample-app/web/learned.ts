// Planted examples for the rules in packages/core/src/rules/more.ts. Each line below should fire one rule.
import jwt from "jsonwebtoken";
import _ from "lodash";
import { WebSocketServer } from "ws";
import { ApolloServer } from "@apollo/server";

export async function invoice(req, res) {
  const inv = await prisma.invoice.findUnique({ where: { id: req.params.id } });
  res.json(inv);
}
export const who = (t: string) => jwt.verify(t, publicKey);
export const token = (id: string) => jwt.sign({ id }, "secret123", { expiresIn: "1h" });
export const save = (req) => _.merge({}, defaults, req.body);
export const wss = new WebSocketServer({ port: 8080 });
export const check = (req) => req.headers["x-signature"] == process.env.WEBHOOK_SECRET;
export const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
