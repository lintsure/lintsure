// Planted examples: user text in the system prompt, model output run as code, no output limit.
export async function ask(req: any, openai: any) {
  const messages = [{ role: "system", content: `You are a helper for ${req.body.company}` }];
  const completion = await openai.chat.completions.create({ model: "gpt-4o", messages });
  eval(completion.choices[0].message.content);
}
