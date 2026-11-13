// Planted issues for tests. One per rule.
declare const posthog: any, db: any, user: any, req: any, app: any, res: any, md5: (s: string) => string;
posthog.identify(user.id, { email: user.email });
fetch(`/api/reset?email=${user.email}`);
const hash = md5(user.password);
const agent = new (require("https").Agent)({ rejectUnauthorized: false });
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
app.use(cors({ origin: "*", credentials: true }));
res.cookie("session", user.token, { httpOnly: false });
