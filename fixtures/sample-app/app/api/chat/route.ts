import { streamText, isLoopFinished } from "ai";

export async function POST(req: Request) {
  const { messages, system } = await req.json();
  const result = streamText({ model: "openai/gpt-5", system, messages, stopWhen: isLoopFinished(), maxOutputTokens: 800, onFinish: async ({ text }) => saveChat(text) });
  return result.toUIMessageStreamResponse();
}
