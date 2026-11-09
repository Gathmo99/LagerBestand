// Edge Function: Admins dürfen das Passwort anderer Nutzer setzen.
// Deploy: supabase functions deploy admin-set-password
// Nutzt SUPABASE_URL, SUPABASE_ANON_KEY und SUPABASE_SERVICE_ROLE_KEY (werden von Supabase automatisch bereitgestellt).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const url = Deno.env.get("SUPABASE_URL")!;
  const caller = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
  });
  const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

  const { data: { user } } = await caller.auth.getUser();
  if (!user) return reply({ error: "Nicht angemeldet." }, 401);

  const { data: profile } = await admin.from("lager_profiles").select("role").eq("id", user.id).single();
  if (profile?.role !== "admin") return reply({ error: "Nur Admins dürfen das." }, 403);

  const { userId, password } = await req.json().catch(() => ({}));
  if (!userId || typeof password !== "string" || password.length < 6) {
    return reply({ error: "userId und Passwort (mind. 6 Zeichen) nötig." }, 400);
  }

  const { error } = await admin.auth.admin.updateUserById(userId, { password });
  if (error) return reply({ error: error.message }, 400);
  return reply({ ok: true });
});
