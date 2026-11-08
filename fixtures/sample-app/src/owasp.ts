// Planted OWASP Top 10:2025 issues for tests. One or more per rule.
declare const fs: any, res: any, req: any, app: any, multer: any, jwt: any, User: any, db: any, logger: any, el: any, crypto: any, exec: any, fsp: any;
fs.readFile(req.query.file, () => {});
res.redirect(req.query.next);
await fetch(req.body.url);
const csrfConfig = { csrf: false };
fs.chmodSync("/tmp/data", 0o777);
const resetToken = Math.random().toString(36);
const c = crypto.createCipher("aes192", "key");
const claims = jwt.decode(token);
exec(`convert ${req.body.file} out.png`);
eval(req.query.code);
el.innerHTML = userBio;
User.find(req.body);
const upload = multer({ dest: "uploads/" });
await User.create(req.body);
const dbConfig = { password: "Hunter2024" };
const signed = jwt.sign({ id: 1 }, secretKey);
if (req.cookies.isAdmin) grantAll();
logger.info("auth header", req.headers.authorization);
logger.info("search", req.query);
try { risky(); } catch (e) {}
app.use((err: any, req2: any, res2: any, next: any) => res.status(500).send(err.stack));
