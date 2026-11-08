// Near misses for OWASP rules: none of these should be flagged.
declare const fs: any, res: any, req: any, app: any, multer: any, jwt: any, User: any, logger: any, el: any, crypto: any, execFile: any, path: any, model: any;
fs.readFile(path.join(BASE, "readme.md"), () => {});
res.redirect("/dashboard");
await fetch("https://api.example.com/rates");
const csrfConfig = { csrf: true };
fs.chmodSync("/tmp/data", 0o600);
const resetToken = crypto.randomBytes(32).toString("hex");
const jitter = Math.random() * 100;
const c = crypto.createCipheriv("aes-256-gcm", key, iv);
const claims = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
execFile("convert", [input, "out.png"]);
model.eval();
el.textContent = userBio;
User.find({ email: String(req.body.email) });
const upload = multer({ dest: "uploads/", limits: { fileSize: 1_000_000 } });
await User.create({ name: req.body.name });
const field = { type: "password", label: "Password" };
const signed = jwt.sign({ id: 1 }, secretKey, { expiresIn: "15m" });
logger.info("token refreshed", { userId });
try { risky(); } catch (e) { logger.error("risky failed", { message: e.message }); }
res.status(500).json({ error: "Something went wrong" });
