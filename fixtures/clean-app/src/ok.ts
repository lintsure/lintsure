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
