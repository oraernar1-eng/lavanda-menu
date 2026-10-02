// Минимальный клиент S3-совместимых хранилищ (Cloudflare R2, Tigris и прочие).
// Без внешних библиотек: подпись AWS Signature V4 считается вручную.
import crypto from "crypto";

const esc = s => encodeURIComponent(s).replace(/[!'()*]/g,
  c => "%" + c.charCodeAt(0).toString(16).toUpperCase());
const escPath = p => p.split("/").map(esc).join("/");
const sha256 = b => crypto.createHash("sha256").update(b).digest("hex");
const hmac = (k, d) => crypto.createHmac("sha256", k).update(d).digest();

export function makeS3({ endpoint, region = "auto", bucket, key, secret }) {
  const base = new URL(endpoint);

  async function call(method, objectKey = "", { query = {}, body = null, extra = {} } = {}) {
    const amzDate = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
    const day = amzDate.slice(0, 8);
    const payload = body ? sha256(body) : sha256("");

    const uri = "/" + esc(bucket) + (objectKey ? "/" + escPath(objectKey) : "");
    const qs = Object.keys(query).sort()
      .map(k => esc(k) + "=" + esc(String(query[k]))).join("&");

    // подписываем минимум: host и два служебных заголовка
    const signedMap = {
      host: base.host,
      "x-amz-content-sha256": payload,
      "x-amz-date": amzDate
    };
    const names = Object.keys(signedMap).sort();
    const canonicalHeaders = names.map(n => n + ":" + String(signedMap[n]).trim() + "\n").join("");
    const signedHeaders = names.join(";");

    const canonical = [method, uri, qs, canonicalHeaders, signedHeaders, payload].join("\n");
    const scope = `${day}/${region}/s3/aws4_request`;
    const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");

    let k = hmac("AWS4" + secret, day);
    k = hmac(k, region); k = hmac(k, "s3"); k = hmac(k, "aws4_request");
    const signature = crypto.createHmac("sha256", k).update(toSign).digest("hex");

    const headers = {
      "x-amz-content-sha256": payload,
      "x-amz-date": amzDate,
      Authorization: `AWS4-HMAC-SHA256 Credential=${key}/${scope}, ` +
                     `SignedHeaders=${signedHeaders}, Signature=${signature}`,
      ...extra                       // Content-Type и Cache-Control не подписываем — так можно
    };

    return fetch(base.origin + uri + (qs ? "?" + qs : ""), { method, headers, body });
  }

  return {
    async get(objectKey) {
      const r = await call("GET", objectKey);
      if (r.status === 404) return null;
      if (!r.ok) throw new Error("S3 GET " + r.status + " " + (await r.text()).slice(0, 200));
      return { buf: Buffer.from(await r.arrayBuffer()), type: r.headers.get("content-type") };
    },
    async put(objectKey, buf, type, cacheControl) {
      const r = await call("PUT", objectKey, {
        body: buf,
        extra: { "Content-Type": type || "application/octet-stream",
                 ...(cacheControl ? { "Cache-Control": cacheControl } : {}) }
      });
      if (!r.ok) throw new Error("S3 PUT " + r.status + " " + (await r.text()).slice(0, 200));
    },
    async del(objectKey) {
      const r = await call("DELETE", objectKey);
      if (!r.ok && r.status !== 404) throw new Error("S3 DELETE " + r.status);
    },
    async list(prefix) {
      const r = await call("GET", "", { query: { "list-type": "2", prefix } });
      if (!r.ok) throw new Error("S3 LIST " + r.status + " " + (await r.text()).slice(0, 200));
      const xml = await r.text();
      return [...xml.matchAll(/<Key>([^<]+)<\/Key>/g)]
        .map(m => m[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">"))
        .sort();
    }
  };
}
