const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const E = process.env;
const GRAPH = "https://graph.facebook.com/v23.0";
const app = express();

// raw body দরকার Meta-র সিগনেচার যাচাইয়ের জন্য
app.use(express.json({ verify: (req, _res, buf) => { req.raw = buf; } }));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ---- ডাটা রাখার জায়গা (সহজ JSON ফাইল) ----
const FILE = path.join(__dirname, "data.json");
let DB = {};
try { DB = JSON.parse(fs.readFileSync(FILE, "utf8")); } catch (e) { DB = {}; }
const save = () => fs.writeFile(FILE, JSON.stringify(DB), () => {});

function add(platform, cid, name, dir, text) {
  const id = platform + ":" + cid;
  const c = DB[id] || (DB[id] = { id, platform, cid, name: "", unread: 0, updated: 0, messages: [] });
  if (name) c.name = name;
  c.messages.push({ dir, text, t: Date.now() });
  c.updated = Date.now();
  if (dir === "in") c.unread++;
  save();
}

// ---- Meta webhook: যাচাই ----
app.get("/webhook", (req, res) => {
  const q = req.query;
  if (q["hub.mode"] === "subscribe" && q["hub.verify_token"] === E.VERIFY_TOKEN) {
    return res.send(q["hub.challenge"]);
  }
  res.sendStatus(403);
});

// ---- Meta webhook: নতুন মেসেজ ----
app.post("/webhook", (req, res) => {
  if (E.APP_SECRET) {
    const sig = req.get("x-hub-signature-256") || "";
    const want = "sha256=" + crypto.createHmac("sha256", E.APP_SECRET).update(req.raw).digest("hex");
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) {
      return res.sendStatus(401);
    }
  }
  const b = req.body || {};
  try {
    if (b.object === "whatsapp_business_account") {
      for (const en of b.entry || []) {
        for (const ch of en.changes || []) {
          const v = ch.value || {};
          for (const m of v.messages || []) {
            const ct = (v.contacts || []).find((c) => c.wa_id === m.from);
            const name = ct && ct.profile ? ct.profile.name : "";
            add("wa", m.from, name, "in", m.type === "text" ? m.text.body : "[" + m.type + "]");
          }
        }
      }
    } else if (b.object === "page" || b.object === "instagram") {
      const p = b.object === "page" ? "fb" : "ig";
      for (const en of b.entry || []) {
        for (const ev of en.messaging || []) {
          if (ev.message && !ev.message.is_echo) {
            add(p, ev.sender.id, "", "in", ev.message.text || "[মিডিয়া]");
          }
        }
      }
    }
  } catch (e) { console.error(e); }
  res.sendStatus(200);
});

// ---- অ্যাপের API (পাসওয়ার্ড দিয়ে সুরক্ষিত) ----
const auth = (req, res, next) =>
  E.ADMIN_PASSWORD && req.get("x-pass") === E.ADMIN_PASSWORD ? next() : res.sendStatus(401);

app.get("/api/ping", auth, (_req, res) => res.json({ ok: 1 }));

app.get("/api/conversations", auth, (_req, res) => {
  const list = Object.values(DB)
    .sort((a, b) => b.updated - a.updated)
    .map((c) => ({
      id: c.id, platform: c.platform, cid: c.cid, name: c.name,
      unread: c.unread, updated: c.updated, last: c.messages[c.messages.length - 1],
    }));
  res.json(list);
});

app.get("/api/conversations/:id", auth, (req, res) => {
  const c = DB[req.params.id];
  if (!c) return res.sendStatus(404);
  c.unread = 0;
  save();
  res.json(c);
});

app.post("/api/conversations/:id/reply", auth, async (req, res) => {
  const c = DB[req.params.id];
  const text = ((req.body && req.body.text) || "").trim();
  if (!c || !text) return res.sendStatus(400);
  try {
    let r;
    if (c.platform === "wa") {
      r = await fetch(`${GRAPH}/${E.WA_PHONE_ID}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + E.WA_TOKEN },
        body: JSON.stringify({ messaging_product: "whatsapp", to: c.cid, type: "text", text: { body: text } }),
      });
    } else {
      r = await fetch(`${GRAPH}/me/messages?access_token=${E.PAGE_TOKEN}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recipient: { id: c.cid }, messaging_type: "RESPONSE", message: { text } }),
      });
    }
    if (!r.ok) {
      const err = await r.text();
      console.error("Meta error:", err);
      return res.status(502).json({ error: err });
    }
    add(c.platform, c.cid, "", "out", text);
    res.json({ ok: 1 });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.listen(E.PORT || 3000, () => console.log("চালু আছে: পোর্ট " + (E.PORT || 3000)));
