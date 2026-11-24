import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader, SeverityBadge } from "@/components/ui-bits";
import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { runScanFn, listScansFn, osintStatusFn } from "@/lib/scan.functions";
import type { ScanReport } from "@/lib/scan-engine.server";
import { Search, Loader2, ShieldCheck, ShieldAlert, ShieldX, Copy, Sparkles, Download, History } from "lucide-react";

export const Route = createFileRoute("/scanner")({
  head: () => ({
    meta: [
      { title: "AI URL Scanner — Sentinel OSINT" },
      { name: "description", content: "Live URL threat analysis: TLS, security headers, DNS, WHOIS, VirusTotal, URLHaus and Safe Browsing fused into one explainable score." },
      { property: "og:title", content: "AI URL Scanner — Sentinel OSINT" },
      { property: "og:description", content: "Run a real security assessment on any URL and get an explainable threat score." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <AppShell><Scanner /></AppShell>,
});

const TONE: Record<string, { text: string; bg: string; border: string }> = {
  safe: { text: "text-safe", bg: "bg-safe", border: "border-safe" },
  medium: { text: "text-medium", bg: "bg-medium", border: "border-medium" },
  critical: { text: "text-critical", bg: "bg-critical", border: "border-critical" },
};

function Scanner() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<ScanReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const scan = useServerFn(runScanFn);
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: (target: string) => scan({ data: { target, scanType: "url" as const } }),
    onSuccess: (res) => { setResult(res.report as ScanReport); setErr(null); qc.invalidateQueries({ queryKey: ["scan-history"] }); },
    onError: (e: Error) => { setErr(e.message); setResult(null); },
  });

  const history = useQuery({
    queryKey: ["scan-history"],
    queryFn: () => listScansFn({ data: { limit: 12 } }),
  });

  // Shows whether each OSINT API key is present and correctly formatted.
  const keys = useQuery({ queryKey: ["osint-status"], queryFn: () => osintStatusFn() });


  return (
    <>
      <PageHeader
        kicker="Live URL Security"
        title="Deep URL Threat Analysis"
        subtitle="Real HTTP/TLS probing, DNS + RDAP intelligence and OSINT blocklists, fused into one explainable score."
      />

      <div className="glass rounded-lg p-5 mb-6">
        <form
          className="flex flex-col md:flex-row gap-3"
          onSubmit={(e) => { e.preventDefault(); if (input) mutation.mutate(input); }}
        >
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="https://example.com"
              className="w-full pl-10 pr-4 py-3 rounded-md bg-input border border-border font-mono text-sm outline-none focus:neon-border"
            />
          </div>
          <button
            disabled={mutation.isPending || !input}
            className="px-6 py-3 rounded-md bg-primary text-primary-foreground font-bold uppercase tracking-widest text-xs neon-border disabled:opacity-50 flex items-center gap-2"
          >
            {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
            {mutation.isPending ? "Scanning" : "Analyze"}
          </button>
        </form>
        <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
          <span>Try:</span>
          {["https://google.com", "https://github.com", "http://neverssl.com", "https://testsafebrowsing.appspot.com/s/phishing.html"].map(x => (
            <button key={x} type="button" onClick={() => { setInput(x); mutation.mutate(x); }} className="px-2 py-0.5 rounded border border-border hover:border-primary">
              {x}
            </button>
          ))}
        </div>
      </div>

      {keys.data && (
        <div className="glass rounded-lg p-4 mb-6">
          <SectionHeader title="OSINT Source Health" subtitle="Which intelligence feeds are ready to use" />
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {keys.data.map((k) => (
              <div key={k.source} className="flex items-start justify-between gap-3 rounded bg-secondary/40 px-3 py-2 text-xs">
                <span className="font-semibold shrink-0">{k.source}</span>
                <span className={k.ok ? "text-safe text-right" : "text-medium text-right"}>{k.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {mutation.isPending && (
        <div className="glass rounded-lg p-10 text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <div className="mt-4 text-sm text-muted-foreground">Fetching target · resolving DNS · querying RDAP + OSINT feeds · generating AI explanation…</div>
        </div>
      )}

      {err && !mutation.isPending && (
        <div className="glass rounded-lg p-5 border-l-4 border-critical text-sm">
          <span className="text-critical font-bold">Scan failed. </span>{err}
        </div>
      )}

      {result && !mutation.isPending && <Result r={result} />}

      <div className="glass rounded-lg p-5 mt-6">
        <SectionHeader title="Recent Scans" subtitle="Every run is stored and searchable" right={<History className="h-4 w-4 text-muted-foreground" />} />
        {history.isLoading ? (
          <div className="text-xs text-muted-foreground">Loading history…</div>
        ) : !history.data?.length ? (
          <div className="text-xs text-muted-foreground">No scans stored yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-[10px] uppercase tracking-widest text-muted-foreground">
                <tr className="border-b border-border/60">
                  <th className="text-left py-2">Target</th><th className="text-left">Verdict</th>
                  <th className="text-left">Threat</th><th className="text-left">Security</th><th className="text-left">When</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((s) => (
                  <tr key={s.id} className="border-b border-border/30">
                    <td className="py-2 font-mono truncate max-w-[280px]">{s.target}</td>
                    <td><SeverityBadge level={s.verdict ?? "unknown"} /></td>
                    <td className="tabular-nums">{s.threat_score}</td>
                    <td className="tabular-nums">{s.security_score}</td>
                    <td className="text-muted-foreground">{new Date(s.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

function download(name: string, content: string, mime: string) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

function Result({ r }: { r: ScanReport }) {
  const Verdict = r.verdict === "safe" ? ShieldCheck : r.verdict === "suspicious" ? ShieldAlert : ShieldX;
  const tone = TONE[r.verdict === "safe" ? "safe" : r.verdict === "suspicious" ? "medium" : "critical"];

  const csv = () => {
    const rows = [["check", "status", "severity", "detail"], ...r.vulns.map((v) => [v.name, v.status, v.severity, v.detail.replace(/"/g, "'")])];
    download(`scan-${r.host}.csv`, rows.map((x) => x.map((c) => `"${c}"`).join(",")).join("\n"), "text/csv");
  };

  return (
    <div className="space-y-6">
      <div className={`glass rounded-lg p-6 relative overflow-hidden border-l-4 ${tone.border}`}>
        <div className={`absolute -right-10 -top-10 h-40 w-40 rounded-full ${tone.bg}/20 blur-3xl`} />
        <div className="flex flex-wrap items-center gap-4">
          <Verdict className={`h-12 w-12 ${tone.text}`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span className="uppercase tracking-widest">Scan target</span>
              <button onClick={() => navigator.clipboard.writeText(r.target)}><Copy className="h-3 w-3" /></button>
              <span>· {(r.durationMs / 1000).toFixed(1)}s</span>
            </div>
            <div className="font-mono text-sm truncate">{r.target}</div>
            <div className="mt-2 flex items-center gap-3 flex-wrap">
              <SeverityBadge level={r.verdict} />
              <span className="text-xs text-muted-foreground">Category: <span className="text-foreground">{r.category}</span></span>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Metric label="Threat" value={r.threatScore} className={tone.text} />
            <Metric label="Security" value={r.securityScore} className="text-safe" />
            <Metric label="Attack Prob." value={`${r.attackProbability}%`} className="text-high" />
            <Metric label="Confidence" value={`${r.confidence}%`} className="neon-text" />
          </div>
        </div>
        <div className="mt-4 flex gap-2">
          <button onClick={csv} className="px-3 py-1.5 rounded border border-border text-xs flex items-center gap-2 hover:border-primary">
            <Download className="h-3 w-3" /> CSV
          </button>
          <button onClick={() => download(`scan-${r.host}.json`, JSON.stringify(r, null, 2), "application/json")}
            className="px-3 py-1.5 rounded border border-border text-xs flex items-center gap-2 hover:border-primary">
            <Download className="h-3 w-3" /> JSON report
          </button>
          <button onClick={() => window.print()} className="px-3 py-1.5 rounded border border-border text-xs flex items-center gap-2 hover:border-primary">
            <Download className="h-3 w-3" /> PDF (print)
          </button>
        </div>
      </div>

      {r.explanation && (
        <div className="glass rounded-lg p-5">
          <SectionHeader title="AI Risk Explanation" subtitle="Generated from this scan's live telemetry" />
          <p className="text-sm leading-relaxed">{r.explanation}</p>
        </div>
      )}

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="glass rounded-lg p-5 lg:col-span-2">
          <SectionHeader title="Explainable AI · Feature Attribution" subtitle="Signed contribution of each feature to the threat score" />
          <div className="space-y-3">
            {r.signals.map(s => (
              <div key={s.name}>
                <div className="flex justify-between text-xs mb-1">
                  <span>{s.name} <span className="text-muted-foreground">· {s.detail}</span></span>
                  <span className={s.direction === "risk" ? "text-critical" : "text-safe"}>
                    {s.direction === "risk" ? "+" : "−"}{Math.abs(s.weight)}
                  </span>
                </div>
                <div className="h-2 rounded bg-secondary overflow-hidden">
                  <div className={`h-full ${s.direction === "risk" ? "bg-critical" : "bg-safe"}`} style={{ width: `${Math.min(100, Math.abs(s.weight) * 2.5)}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="glass rounded-lg p-5">
          <SectionHeader title="Domain Intelligence" />
          <dl className="text-xs space-y-2">
            {Object.entries(r.domain).map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3 border-b border-border/40 pb-1.5">
                <dt className="text-muted-foreground uppercase tracking-wider text-[10px]">{k}</dt>
                <dd className="font-mono truncate max-w-[60%] text-right">{String(v)}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="glass rounded-lg p-5">
          <SectionHeader title="Attack Probability Model" />
          <div className="space-y-2">
            {r.probabilities.map(p => (
              <div key={p.name}>
                <div className="flex justify-between text-xs mb-1"><span>{p.name}</span><span className="tabular-nums">{p.value}%</span></div>
                <div className="h-2 rounded bg-secondary overflow-hidden"><div className="h-full bg-high" style={{ width: `${p.value}%` }} /></div>
              </div>
            ))}
          </div>
        </div>

        <div className="glass rounded-lg p-5">
          <SectionHeader title="OSINT Source Verdicts" />
          <div className="space-y-2">
            {r.intel.map(s => (
              <div key={s.source} className="flex items-center justify-between p-2 rounded bg-secondary/40 text-xs gap-3">
                <span className="font-semibold">{s.source}</span>
                <span className={!s.enabled ? "text-muted-foreground" : s.hits > 0 ? "text-critical" : "text-safe"}>{s.verdict}</span>
              </div>
            ))}
          </div>
          {r.technologies.length > 0 && (
            <>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-4 mb-2">Detected Technologies</div>
              <div className="flex flex-wrap gap-1.5">
                {r.technologies.map(t => <span key={t} className="px-2 py-0.5 rounded border border-border text-[10px]">{t}</span>)}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="glass rounded-lg p-5">
        <SectionHeader title="Threat Category Detection" />
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {r.categoryFlags.map(c => (
            <div key={c.label} className={`px-3 py-2 rounded border text-xs flex items-center justify-between ${c.hit ? "border-critical/60 bg-critical/10 text-critical" : "border-border bg-secondary/30 text-muted-foreground"}`}>
              <span>{c.label}</span>
              <span className="text-[10px] font-bold">{c.hit ? "HIT" : "clear"}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="glass rounded-lg p-5">
        <SectionHeader title="Vulnerability & Security Header Audit" subtitle="OWASP / MITRE mapped, with remediation" />
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-[10px] uppercase tracking-widest text-muted-foreground">
              <tr className="border-b border-border/60">
                <th className="text-left py-2">Check</th><th className="text-left">Status</th>
                <th className="text-left">Detail</th><th className="text-left">Mapping</th><th className="text-left">Remediation</th>
              </tr>
            </thead>
            <tbody>
              {r.vulns.map(v => (
                <tr key={v.name} className="border-b border-border/30 align-top">
                  <td className="py-2 font-medium">{v.name}</td>
                  <td><SeverityBadge level={v.status} /></td>
                  <td className="text-muted-foreground max-w-[260px]">{v.detail}</td>
                  <td className="text-muted-foreground">{[v.owasp, v.mitre].filter(Boolean).join(" · ") || "—"}</td>
                  <td className="text-muted-foreground max-w-[260px]">{v.remediation ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="glass rounded-lg p-5">
        <SectionHeader title="AI Remediation Plan" />
        <ul className="space-y-2 text-sm">
          {r.recommendations.map((rec, i) => (
            <li key={i} className="flex gap-3">
              <span className={`h-6 w-6 shrink-0 rounded-full ${tone.bg}/20 ${tone.text} flex items-center justify-center text-xs font-bold`}>{i + 1}</span>
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      </div>

      {r.probeErrors.length > 0 && (
        <div className="glass rounded-lg p-4 text-[11px] text-muted-foreground">
          <span className="uppercase tracking-widest">Probe notes:</span> {r.probeErrors.join(" · ")}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, className }: { label: string; value: string | number; className?: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={`text-3xl font-bold tabular-nums ${className ?? ""}`}>{value}</div>
    </div>
  );
}
