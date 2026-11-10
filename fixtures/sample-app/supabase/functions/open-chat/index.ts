// Planted: no caller check, and it spends the project's OpenAI key.
Deno.serve(async (req) => {
  const { question } = await req.json();
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${Deno.env.get("OPENAI_API_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model: "gpt-4o-mini", max_tokens: 200, messages: [{ role: "user", content: question }] }),
  });
  return new Response(await r.text());
});
