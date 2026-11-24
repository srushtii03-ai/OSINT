import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

const TYPES = ["url", "domain", "ip", "file", "email"] as const;

/** Saves a finished report and creates an alert when it is not safe. */
async function persist(type: string, report: any) {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  const { data: row } = await supabaseAdmin
    .from("scans")
    .insert({
      scan_type: type,
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

  if (report.verdict !== "safe" && row?.id) {
    await supabaseAdmin.from("alerts").insert({
      scan_id: row.id,
      severity: report.verdict === "malicious" ? "critical" : "medium",
      title: `${report.category} — ${report.host}`,
      message: report.explanation ?? `Threat score ${report.threatScore}/100`,
      target: report.target,
    });
  }

  await supabaseAdmin.from("audit_logs").insert({
    action: `api.scan.${type}`,
    resource: report.host,
    detail: { verdict: report.verdict, threatScore: report.threatScore },
  });

  return row?.id ?? null;
}

export const Route = createFileRoute("/api/public/scan/$type")({
  server: {
    handlers: {
      POST: async ({ request, params }) => {
        const type = params.type as (typeof TYPES)[number];
        if (!TYPES.includes(type)) {
          return Response.json({ error: `Unsupported scan type "${params.type}"` }, { status: 400 });
        }

        let body: any;
        try {
          body = await request.json();
        } catch {
          return Response.json({ error: "Invalid JSON body" }, { status: 400 });
        }

        try {
          // ---- Email: expects { raw: "<full email or address>" } ----------
          if (type === "email") {
            const { raw } = z.object({ raw: z.string().trim().min(3).max(200_000) }).parse(body);
            const { scanEmail } = await import("@/lib/email-scan.server");
            const report = await scanEmail(raw);
            return Response.json({ id: await persist("email", report), ...report });
          }

          // ---- File: expects { fileName, contentBase64 } -------------------
          if (type === "file") {
            const { fileName, contentBase64 } = z
              .object({ fileName: z.string().trim().min(1).max(300), contentBase64: z.string().min(4).max(14_000_000) })
              .parse(body);
            const { scanFile } = await import("@/lib/file-scan.server");
            const binary = atob(contentBase64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            const report = await scanFile(bytes, fileName);
            return Response.json({ id: await persist("file", report), ...report });
          }

          // ---- URL / domain / IP: expects { target } ------------------------
          const { target } = z.object({ target: z.string().trim().min(3).max(2048) }).parse(body);
          const { runScan } = await import("@/lib/scan-engine.server");
          const report = await runScan(target, type);
          return Response.json({ id: await persist(type, report), ...report });
        } catch (error) {
          if (error instanceof z.ZodError) {
            return Response.json({ error: "Invalid body", issues: error.issues }, { status: 400 });
          }
          console.error("scan api error", error);
          return Response.json({ error: String(error).slice(0, 300) }, { status: 500 });
        }
      },
    },
  },
});
