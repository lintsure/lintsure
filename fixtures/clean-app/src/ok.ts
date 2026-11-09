// Near misses: none of these should be flagged.
declare const posthog: any, db: any, user: any, app: any, res: any, logger: any, argon2: any;
posthog.identify(user.id);
logger.info(`signup ${user.id}`);
fetch("https://payments.example.com/charge");
fetch("http://localhost:3000/health");
fetch(`/api/reset?id=${user.id}`);
const hash = await argon2.hash(user.password);
db.query("SELECT * FROM users WHERE id = $1", [user.id]);
app.use(cors({ origin: ["https://lintsure.com"] }));
res.cookie("session", user.token, { httpOnly: true, secure: true });
const DEBUG_LEVEL = "info";
declare const openai: any, classifier: any, x: any, analyzeSentiment: any, text: string;
const res = await openai.chat.completions.create({ model: "gpt", messages: [], max_tokens: 200 });
const label = classifier.predict(x);
const system = "You are an AI assistant. Tell users you are an AI.";
const sentiment = analyzeSentiment(text);
logger.info({ model: "gpt", label, at: Date.now() }); // record of the AI calls above
