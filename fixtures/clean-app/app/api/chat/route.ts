import { streamText, stepCountIs } from "ai";

export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({ model: "openai/gpt-5", system: "You answer questions about our docs.", messages, stopWhen: stepCountIs(5), maxOutputTokens: 800, onFinish: async ({ text }) => saveChat(text) });
  return result.toUIMessageStreamResponse();
}
