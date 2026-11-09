// Near misses: fixed system prompt, user text as its own message, output shown as text, a limit set.
export async function ask(req: any, openai: any, logger: any) {
  const messages = [{ role: "system", content: "You are a helpful assistant." }, { role: "user", content: req.body.question }];
  const completion = await openai.chat.completions.create({ model: "gpt-4o", messages, max_tokens: 500 });
  logger.info("ai call", { model: "gpt-4o" });
  return completion.choices[0].message.content;
}
