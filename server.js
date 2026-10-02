import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";
import cookieParser from "cookie-parser";
import sharp from "sharp";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PASS = process.env.ADMIN_PASSWORD || "lavanda";
const SECRET = process.env.SESSION_SECRET || "change-me-please";

/* ─────────────────────────────────────────────────────────────
   Хранилище.
   Если заданы ключи — меню и фото живут в объектном хранилище
   (Tigris на Fly или Cloudflare R2). Диск тогда не нужен.
   Если ключей нет — всё ложится в локальную папку, для проверки
   на своём компьютере.
   ───────────────────────────────────────────────────────────── */
const BUCKET   = process.env.BUCKET_NAME || process.env.R2_BUCKET || "";
const ENDPOINT = process.env.AWS_ENDPOINT_URL_S3 ||
  (process.env.R2_ACCOUNT_ID ? `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : "");
const KEY      = process.env.AWS_ACCESS_KEY_ID || process.env.R2_ACCESS_KEY_ID || "";
const SECRETK  = process.env.AWS_SECRET_ACCESS_KEY || process.env.R2_SECRET_ACCESS_KEY || "";
const CLOUD    = Boolean(BUCKET && ENDPOINT && KEY && SECRETK);

const LOCAL = process.env.DATA_DIR || path.join(__dirname, "data");
let s3 = null;

if (CLOUD) {
  const { S3Client, GetObjectCommand, PutObjectCommand, ListObjectsV2Command, DeleteObjectCommand } =
    await import("@aws-sdk/client-s3");
  const client = new S3Client({
    region: process.env.AWS_REGION || "auto",
    endpoint: ENDPOINT,
    forcePathStyle: true,
    credentials: { accessKeyId: KEY, secretAccessKey: SECRETK }
  });
  const body = async (r) => Buffer.concat(await r.Body.toArray());
  s3 = {
    async get(key) {
      try {
        const r = await client.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
        return { buf: await body(r), type: r.ContentType };
      } catch { return null; }
    },
    put: (key, buf, type) => client.send(new PutObjectCommand({
      Bucket: BUCKET, Key: key, Body: buf, ContentType: type,
      CacheControl: key.startsWith("dishes/") ? "public, max-age=31536000, immutable" : "no-store"
    })),
    list: async (prefix) => {
      const r = await client.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix }));
      return (r.Contents || []).map(o => o.Key).sort();
    },
    del: (key) => client.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }))
  };
  console.log("Хранилище: облако, бакет " + BUCKET);
} else {
  fs.mkdirSync(path.join(LOCAL, "dishes"), { recursive: true });
  console.log("Хранилище: локальная папка " + LOCAL);
}

const store = {
  async get(key) {
    if (s3) return s3.get(key);
    const p = path.join(LOCAL, key);
    return fs.existsSync(p) ? { buf: fs.readFileSync(p) } : null;
  },
  async put(key, buf, type) {
    if (s3) return s3.put(key, buf, type);
    const p = path.join(LOCAL, key);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, buf);
  },
  async list(prefix) {
    if (s3) return s3.list(prefix);
    const d = path.join(LOCAL, prefix);
    return fs.existsSync(d) ? fs.readdirSync(d).sort().map(f => prefix + f) : [];
  },
  async del(key) {
    if (s3) return s3.del(key);
    try { fs.unlinkSync(path.join(LOCAL, key)); } catch {}
  }
};

/* ── меню: держим в памяти, в хранилище пишем при сохранении ── */
let cache = null;
const stamp = (b) => '"' + crypto.createHash("sha1").update(b).digest("hex").slice(0, 16) + '"';

async function menu() {
  if (cache) return cache;
  let got = await store.get("menu.json");
  if (!got) {
    const seed = fs.readFileSync(path.join(__dirname, "seed", "menu.json"));
    await store.put("menu.json", seed, "application/json");
    got = { buf: seed };
    console.log("Меню создано из seed/menu.json");
  }
  const body = got.buf.toString("utf8");
  cache = { body, tag: stamp(body) };
  return cache;
}

const app = express();
app.set("etag", false);
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

/* ── вход ──────────────────────────────────────────── */
const sign = v => v + "." + crypto.createHmac("sha256", SECRET).update(v).digest("hex");
const valid = c => {
  if (!c) return false;
  const i = c.lastIndexOf(".");
  if (i < 0) return false;
  const v = c.slice(0, i);
  try {
    return crypto.timingSafeEqual(Buffer.from(sign(v)), Buffer.from(c)) && Number(v) > Date.now();
  } catch { return false; }
};
const guard = (req, res, next) =>
  valid(req.cookies.lav) ? next() : res.status(401).json({ error: "Нужен вход" });

app.post("/api/login", (req, res) => {
  const given = String(req.body?.password || "");
  const ok = given.length === PASS.length && crypto.timingSafeEqual(
    Buffer.from(given.padEnd(64, "\0")), Buffer.from(PASS.padEnd(64, "\0")));
  if (!ok) return res.status(401).json({ error: "Неверный пароль" });
  res.cookie("lav", sign(String(Date.now() + 12 * 3600e3)), {
    httpOnly: true, sameSite: "lax",
    secure: process.env.NODE_ENV === "production", maxAge: 12 * 3600e3
  });
  res.json({ ok: true });
});
app.post("/api/logout", (req, res) => { res.clearCookie("lav"); res.json({ ok: true }); });
app.get("/api/session", (req, res) => res.json({ auth: valid(req.cookies.lav) }));

/* ── меню ──────────────────────────────────────────── */
app.get("/api/menu", async (req, res) => {
  try {
    const { body, tag } = await menu();
    res.set("ETag", tag).set("Cache-Control", "no-cache");
    if (req.headers["if-none-match"] === tag) return res.status(304).end();
    res.type("application/json").send(body);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Хранилище недоступно" });
  }
});

app.put("/api/menu", guard, async (req, res) => {
  const b = req.body;
  if (!b || !Array.isArray(b.cats) || !b.lunch) return res.status(400).json({ error: "Неверный формат" });
  try {
    const prev = await menu();
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    await store.put(`backups/menu-${ts}.json`, Buffer.from(prev.body), "application/json");
    const keys = await store.list("backups/");
    for (const k of keys.slice(0, -20)) await store.del(k);

    const body = JSON.stringify(b, null, 1);
    await store.put("menu.json", Buffer.from(body), "application/json");
    cache = { body, tag: stamp(body) };
    res.json({ ok: true, savedAt: new Date().toISOString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Не удалось сохранить" });
  }
});

/* ── фото блюд ─────────────────────────────────────── */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024 },
  fileFilter: (req, f, cb) => cb(null, /^image\/(jpeg|png|webp|heic|heif)$/.test(f.mimetype))
});

app.post("/api/upload", guard, upload.single("photo"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Нужна картинка JPG, PNG, WEBP или HEIC до 12 МБ" });
  try {
    const buf = await sharp(req.file.buffer)
      .rotate()
      .resize(900, 900, { fit: "cover", position: "attention" })
      .webp({ quality: 82 })
      .toBuffer();
    const name = Date.now().toString(36) + "-" + crypto.randomBytes(3).toString("hex") + ".webp";
    await store.put("dishes/" + name, buf, "image/webp");
    res.json({ url: "/img/" + name, kb: Math.round(buf.length / 1024) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Не удалось обработать фото" });
  }
});

// фото отдаём через себя: бакет можно не открывать наружу
app.get("/img/:name", async (req, res) => {
  if (!/^[a-z0-9-]+\.webp$/.test(req.params.name)) return res.status(404).end();
  try {
    const got = await store.get("dishes/" + req.params.name);
    if (!got) return res.status(404).end();
    res.set("Content-Type", "image/webp")
       .set("Cache-Control", "public, max-age=31536000, immutable")
       .send(got.buf);
  } catch { res.status(404).end(); }
});

/* ── страницы ──────────────────────────────────────── */
const MEDIA = (process.env.MEDIA_BASE || "").replace(/\/$/, "");
const page = f => fs.readFileSync(path.join(__dirname, "public", f), "utf8").replaceAll("{{MEDIA}}", MEDIA);
const INDEX = page("index.html"), ADMIN = page("admin.html");
const serve = html => (req, res) => res.set("Cache-Control", "public, max-age=300").type("html").send(html);

app.get("/", serve(INDEX));
app.get("/admin", serve(ADMIN));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "365d", immutable: true }));
app.get("/healthz", (req, res) => res.type("text").send("ok"));

app.listen(process.env.PORT || 8080, "0.0.0.0",
  () => console.log("Lavanda на порту " + (process.env.PORT || 8080)));
