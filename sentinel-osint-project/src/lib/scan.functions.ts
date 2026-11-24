import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const ScanInput = z.object({
  target: z.string().trim().min(3).max(2048),
  scanType: z.enum(["url", "domain", "ip", "file", "email"]).default("url"),
});

export type ScanRow = {
  id: string;
  scan_type: string;
  target: string;
  verdict: string | null;
  threat_score: number | null;
  security_score: number | null;
  attack_probability: number | null;
  confidence: number | null;
  category: string | null;
  duration_ms: number | null;
  created_at: string;
  report: unknown;
};

/** Saves any finished report into the database and raises an alert if needed. */
async function persist(
  scanType: string,
  report: {
    target: string; host: string; verdict: string; threatScore: number; securityScore: number;
    attackProbability: number; confidence: number; category: string; durationMs: number; explanation?: string;
  },
) {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  const { data: row, error } = await supabaseAdmin
    .from("scans")
    .insert({
      scan_type: scanType,
      target: report.target,
      normalized_target: report.host,
      status: "completed",
      verdict: report.verdict,
      threat_score: report.threatScore,
      security_score: report.securityScore,
      attack_probability: report.attackProbability,
      confidence: report.confidence,
      category: report.category,
      duration_ms: report.durationMs,
      report: report as never,
    })
    .select("id")
    .single();
  if (error) console.error("scan persist failed", error);

  if (report.verdict !== "safe" && row?.id) {
    await supabaseAdmin.from("alerts").insert({
      scan_id: row.id,
      severity: report.verdict === "malicious" ? "critical" : "medium",
      title: `${report.category} — ${report.host}`,
      message: report.explanation ?? `Threat score ${report.threatScore}/100 on ${report.target}`,
      target: report.target,
    });
  }

  await supabaseAdmin.from("audit_logs").insert({
    action: `scan.${scanType}`,
    resource: report.host,
    detail: { verdict: report.verdict, threatScore: report.threatScore, durationMs: report.durationMs },
  });

  return row?.id ?? null;
}

export const runScanFn = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => ScanInput.parse(input))
  .handler(async ({ data }) => {
    const { runScan } = await import("./scan-engine.server");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    let report;
    try {
      report = await runScan(data.target, data.scanType);
    } catch (error) {
      await supabaseAdmin.from("scans").insert({
        scan_type: data.scanType,
        target: data.target,
        status: "failed",
        error: String(error).slice(0, 500),
      });
      throw new Error(`Scan failed: ${String(error).slice(0, 200)}`);
    }

    const id = await persist(data.scanType, report);
    return { id, report };
  });

/** POST /scan/email — paste a raw email or an address. */
export const scanEmailFn = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => z.object({ raw: z.string().trim().min(3).max(200_000) }).parse(input))
  .handler(async ({ data }) => {
    const { scanEmail } = await import("./email-scan.server");
    const report = await scanEmail(data.raw);
    const id = await persist("email", report);
    return { id, report };
  });

/** POST /scan/file — the file arrives as base64 text so it survives JSON transport. */
export const scanFileFn = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) =>
    z.object({ fileName: z.string().trim().min(1).max(300), contentBase64: z.string().min(4).max(14_000_000) }).parse(input),
  )
  .handler(async ({ data }) => {
    const { scanFile } = await import("./file-scan.server");
    const binary = atob(data.contentBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

    const report = await scanFile(bytes, data.fileName);
    const id = await persist("file", report);
    return { id, report };
  });

export const listScansFn = createServerFn({ method: "GET" })
  .inputValidator((input: unknown) =>
    z
      .object({
        search: z.string().trim().max(200).optional(),
        scanType: z.enum(["url", "domain", "ip", "file", "email"]).optional(),
        limit: z.number().int().min(1).max(100).default(25),
      })
      .parse(input ?? {}),
  )
  .handler(async ({ data }) => {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    let q = supabaseAdmin
      .from("scans")
      .select("id, scan_type, target, verdict, threat_score, security_score, attack_probability, confidence, category, duration_ms, created_at")
      .order("created_at", { ascending: false })
      .limit(data.limit);
    if (data.search) q = q.ilike("target", `%${data.search}%`);
    if (data.scanType) q = q.eq("scan_type", data.scanType);
    const { data: rows, error } = await q;
    if (error) throw new Error(error.message);
    return rows ?? [];
  });

export const getScanFn = createServerFn({ method: "GET" })
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data }) => {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: row, error } = await supabaseAdmin.from("scans").select("*").eq("id", data.id).maybeSingle();
    if (error) throw new Error(error.message);
    return (row ?? null) as never;
  });

/** Tells the UI whether each OSINT API key is present and correctly formatted. */
export const osintStatusFn = createServerFn({ method: "GET" }).handler(async () => {
  const { validateVirusTotalKey, validateSafeBrowsingKey, validateAbuseIpdbKey } = await import("./scan-engine.server");
  const vt = validateVirusTotalKey();
  const gsb = validateSafeBrowsingKey();
  const abuse = validateAbuseIpdbKey();
  return [
    { source: "VirusTotal", ok: vt.ok, detail: vt.ok ? "Key format valid (64 hex characters)" : vt.reason },
    { source: "Google Safe Browsing", ok: gsb.ok, detail: gsb.ok ? "Key format valid" : gsb.reason },
    { source: "AbuseIPDB", ok: abuse.ok, detail: abuse.ok ? "Key format valid" : abuse.reason },
    { source: "URLHaus / MalwareBazaar (abuse.ch)", ok: true, detail: "Free, no key needed" },
    { source: "Cloudflare DNS + RDAP", ok: true, detail: "Free, no key needed" },
  ];
});

