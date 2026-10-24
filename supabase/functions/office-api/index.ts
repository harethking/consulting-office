// office-api — خادم نظام المكتب الاستشاري
// إنشاء الحسابات، حذف المستخدمين، المهندس الذكي (Gemini)، وإدارة مفتاح Gemini للمالك فقط.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const SB_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(SB_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

const EMAIL_DOMAIN = "users.consulting-office.app";
const DEFAULT_MODEL = "gemini-flash-latest";
const ROLES = ["admin", "staff", "contractor"];

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const AI_SYSTEM = `أنت "المهندس الذكي" في نظام مكتب استشاري هندسي في العراق.
قواعد صارمة:
- أجب فقط عن السؤال المطروح، بدون إضافة اقتراحات أو تنبيهات أو مواضيع لم يسألها المستخدم.
- اعتمد فقط على بيانات المشروع المرفقة. لا تخترع أرقاماً أو أحداثاً أو أسماء. إذا لم تتوفر المعلومة في البيانات قل: "هذه المعلومة غير مسجلة في النظام".
- أنت مطّلع على مشروع واحد فقط هو المرفق. إذا سُئلت عن مشروع آخر قل إنك تعرض بيانات المشروع المفتوح فقط.
- عند طلب تقرير أو "شنو الجديد": اذكر ما اكتمل وما تحدّث والفحوصات المضافة ونتائجها والزيارات، واذكر الفقرات المكتملة التي تتطلب فحوصات مختبرية ولم تُسجَّل لها فحوصات.
- أجب بالعربية بأسلوب مهني موجز، وافهم اللهجة العراقية. استخدم **للعناوين** والشرطة - للقوائم، بدون جداول.`;

const AI_SYSTEM_ALL = `أنت "المهندس الذكي" في نظام مكتب استشاري هندسي في العراق، وتحلل اليوم كل المشاريع المسجلة معاً.
قواعد صارمة:
- أجب فقط عن السؤال المطروح، بدون إضافة اقتراحات أو تنبيهات لم يسألها المستخدم.
- اعتمد فقط على بيانات المشاريع المرفقة. لا تخترع أرقاماً أو أسماء. إذا لم تتوفر المعلومة قل: "هذه المعلومة غير مسجلة في النظام".
- عند المقارنة بين المشاريع اذكر اسم كل مشروع ونسبته، ورتّبها عند الحاجة.
- أجب بالعربية بأسلوب مهني موجز، وافهم اللهجة العراقية. استخدم **للعناوين** والشرطة - للقوائم، بدون جداول.`;

type Profile = { id: string; role: string; status: string; is_owner: boolean; name: string };

async function caller(req: Request): Promise<Profile | null> {
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const { data, error } = await admin.auth.getUser(token);
  if (error || !data.user) return null;
  const { data: p } = await admin.from("profiles").select("*").eq("id", data.user.id).maybeSingle();
  return p && p.status === "active" ? (p as Profile) : null;
}

async function getSecrets() {
  const { data } = await admin.from("app_secrets").select("k,v").in("k", ["gemini_key", "gemini_model"]);
  const m: Record<string, string> = {};
  (data || []).forEach((r: { k: string; v: string }) => { m[r.k] = r.v; });
  return { key: m.gemini_key || "", model: m.gemini_model || DEFAULT_MODEL };
}

async function register(b: Record<string, unknown>) {
  const name = String(b.name || "").trim().slice(0, 80);
  const username = String(b.username || "").trim().toLowerCase();
  const password = String(b.password || "");
  const company = String(b.company || "").trim().slice(0, 120);
  let role = String(b.role || "staff");
  if (!name) return json({ error: "اكتب الاسم الكامل" }, 400);
  if (!/^[a-z0-9._-]{3,30}$/.test(username)) return json({ error: "اسم المستخدم من 3 إلى 30 حرفاً إنكليزياً أو أرقاماً (بدون مسافات)" }, 400);
  if (password.length < 6) return json({ error: "كلمة المرور 6 أحرف على الأقل" }, 400);
  if (!ROLES.includes(role)) role = "staff";

  const { count } = await admin.from("profiles").select("id", { count: "exact", head: true });
  const first = (count || 0) === 0;
  const { data: exists } = await admin.from("profiles").select("id").eq("username", username).maybeSingle();
  if (exists) return json({ error: "اسم المستخدم مستخدم سابقاً" }, 409);

  const { data: cu, error } = await admin.auth.admin.createUser({
    email: `${username}@${EMAIL_DOMAIN}`, password, email_confirm: true, user_metadata: { name, username },
  });
  if (error || !cu.user) {
    const msg = error?.message || "تعذر إنشاء الحساب";
    return json({ error: /already|registered|exists/i.test(msg) ? "اسم المستخدم مستخدم سابقاً" : msg }, 400);
  }
  const { error: pe } = await admin.from("profiles").insert({
    id: cu.user.id, username, name, company,
    role: first ? "admin" : role, status: first ? "active" : "pending", is_owner: first,
  });
  if (pe) {
    await admin.auth.admin.deleteUser(cu.user.id);
    return json({ error: pe.message }, 500);
  }
  return json({ ok: true, first });
}

async function ai(b: Record<string, unknown>) {
  const { key, model } = await getSecrets();
  if (!key) return json({ error: "المهندس الذكي غير مفعّل" }, 400);
  const question = String(b.question || "").slice(0, 4000);
  const context = String(b.context || "").slice(0, 250000);
  if (!question) return json({ error: "سؤال فارغ" }, 400);
  const contents: { role: string; parts: { text: string }[] }[] = [];
  (Array.isArray(b.history) ? b.history : []).slice(-10).forEach((m: { role?: string; text?: string }) => {
    const role = m && m.role === "model" ? "model" : "user";
    const text = String((m && m.text) || "").slice(0, 8000);
    if (!text || (!contents.length && role === "model")) return;
    const last = contents[contents.length - 1];
    if (last && last.role === role) last.parts[0].text += "\n\n" + text;
    else contents.push({ role, parts: [{ text }] });
  });
  if (contents.length && contents[contents.length - 1].role === "user") contents.pop();
  contents.push({ role: "user", parts: [{ text: question }] });

  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": key },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: (b.scope === "all" ? AI_SYSTEM_ALL : AI_SYSTEM) + "\n\n# البيانات\n" + context }] },
      contents,
      generationConfig: { temperature: 0.2, maxOutputTokens: 3000 },
    }),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) return json({ error: "Gemini: " + ((j as { error?: { message?: string } }).error?.message || res.status) }, 502);
  const parts = (j as { candidates?: { content?: { parts?: { text?: string; thought?: boolean }[] } }[] }).candidates?.[0]?.content?.parts || [];
  const text = parts.filter((p) => !p.thought).map((p) => p.text || "").join("").trim();
  if (!text) return json({ error: "رد فارغ من Gemini" }, 502);
  return json({ text });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  try {
    if (b.action === "register") return await register(b);

    const me = await caller(req);
    if (!me) return json({ error: "غير مصرح" }, 401);

    if (b.action === "ai") return await ai(b);

    if (b.action === "delete-user") {
      if (me.role !== "admin") return json({ error: "للمدير فقط" }, 403);
      const id = String(b.id || "");
      const { data: t } = await admin.from("profiles").select("id,is_owner").eq("id", id).maybeSingle();
      if (!t || t.is_owner || t.id === me.id) return json({ error: "لا يمكن حذف هذا الحساب" }, 400);
      const { error } = await admin.auth.admin.deleteUser(id);
      if (error) return json({ error: error.message }, 500);
      return json({ ok: true });
    }

    // مفتاح Gemini: للمالك (المدير الرئيسي) فقط، ولا يُعاد المفتاح أبداً إلى المتصفح
    if (b.action === "ai-status") {
      if (!me.is_owner) return json({ error: "للمدير الرئيسي فقط" }, 403);
      const s = await getSecrets();
      return json({ enabled: !!s.key, model: s.model });
    }
    if (b.action === "ai-key") {
      if (!me.is_owner) return json({ error: "للمدير الرئيسي فقط" }, 403);
      const key = String(b.key || "").trim();
      const model = String(b.model || "").trim().replace(/^models\//, "");
      if (b.clear) await admin.from("app_secrets").delete().eq("k", "gemini_key");
      else if (key) await admin.from("app_secrets").upsert({ k: "gemini_key", v: key, updated_at: new Date().toISOString() });
      if (model) {
        if (!/^[a-zA-Z0-9._-]{3,80}$/.test(model)) return json({ error: "اسم النموذج غير صالح" }, 400);
        await admin.from("app_secrets").upsert({ k: "gemini_model", v: model, updated_at: new Date().toISOString() });
      }
      const s = await getSecrets();
      await admin.from("office").update({ ai_enabled: !!s.key }).eq("id", 1);
      return json({ enabled: !!s.key, model: s.model });
    }

    return json({ error: "unknown action" }, 400);
  } catch (e) {
    return json({ error: String((e as Error)?.message || e) }, 500);
  }
});
