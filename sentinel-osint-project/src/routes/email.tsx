import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader, SeverityBadge } from "@/components/ui-bits";
import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useMutation } from "@tanstack/react-query";
import { scanEmailFn } from "@/lib/scan.functions";
import type { EmailReport } from "@/lib/email-scan.server";
import { Mail, Loader2, ShieldCheck, ShieldAlert, ShieldX, Link2 } from "lucide-react";

export const Route = createFileRoute("/email")({
  head: () => ({
    meta: [
      { title: "Email Phishing Analyzer — Sentinel OSINT" },
      { name: "description", content: "Paste a raw email to check SPF, DKIM and DMARC, spot spoofed senders, and run OSINT checks on every link inside." },
      { property: "og:title", content: "Email Phishing Analyzer — Sentinel OSINT" },
      { property: "og:description", content: "SMTP header analysis with SPF/DKIM/DMARC checks and link reputation lookups." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <AppShell><EmailAnalyzer /></AppShell>,
});

const SAMPLE = `Return-Path: <bounce@mail-secure-alerts.top>
From: "PayPal Service" <service@paypal-verify-login.top>
Reply-To: support@refund-desk.icu
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
Received: from mail-secure-alerts.top (unknown [45.61.136.12]) by mx.example.com
Subject: Urgent: verify your account within 24 hours

Dear customer, your account will be suspended.
Please verify now: http://paypal-verify-login.top/signin
`;

function EmailAnalyzer() {
  const [raw, setRaw] = useState("");
  const [report, setReport] = useState<EmailReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const scan = useServerFn(scanEmailFn);

  const mutation = useMutation({
    mutationFn: (value: string) => scan({ data: { raw: value } }),
    onSuccess: (res) => { setReport(res.report as EmailReport); setErr(null); },
    onError: (e: Error) => { setErr(e.message); setReport(null); },
  });

  return (
    <>
      <PageHeader
        kicker="Email Security"
        title="Email Phishing Analyzer"
        subtitle="Paste a full email (headers + body) or just an address. We check SPF, DKIM and DMARC, look for spoofing, and scan every link with OSINT sources."
      />

      <div className="glass rounded-lg p-5 mb-6">
        <form onSubmit={(e) => { e.preventDefault(); if (raw) mutation.mutate(raw); }}>
          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            rows={10}
            placeholder="Paste the raw email here (View original / Show source in your mail client), or just type an address."
            className="w-full p-3 rounded-md bg-input border border-border font-mono text-xs outline-none focus:neon-border"
          />
          <div className="mt-3 flex flex-wrap gap-2 items-center">
            <button
              disabled={mutation.isPending || !raw}
              className="px-6 py-3 rounded-md bg-primary text-primary-foreground font-bold uppercase tracking-widest text-xs neon-border disabled:opacity-50 flex items-center gap-2"
            >
              {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Mail className="h-4 w-4" />}
              {mutation.isPending ? "Analyzing" : "Analyze email"}
            </button>
            <button type="button" onClick={() => setRaw(SAMPLE)} className="px-3 py-2 rounded border border-border text-xs hover:border-primary">
              Load phishing sample
            </button>
          </div>
        </form>
      </div>

      {mutation.isPending && (
        <div className="glass rounded-lg p-10 text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <div className="mt-4 text-sm text-muted-foreground">Parsing headers · checking SPF/DKIM/DMARC · scanning every link…</div>
        </div>
      )}

      {err && !mutation.isPending && (
        <div className="glass rounded-lg p-5 border-l-4 border-critical text-sm">
          <span className="text-critical font-bold">Analysis failed. </span>{err}
        </div>
      )}

      {report && !mutation.isPending && <EmailResult r={report} />}
    </>
  );
}

function EmailResult({ r }: { r: EmailReport }) {
  const Icon = r.verdict === "safe" ? ShieldCheck : r.verdict === "suspicious" ? ShieldAlert : ShieldX;
  const tone = r.verdict === "safe" ? "text-safe" : r.verdict === "suspicious" ? "text-medium" : "text-critical";
  const border = r.verdict === "safe" ? "border-safe" : r.verdict === "suspicious" ? "border-medium" : "border-critical";

  return (
    <div className="space-y-6">
      <div className={`glass rounded-lg p-6 border-l-4 ${border} flex flex-wrap items-center gap-5`}>
        <Icon className={`h-12 w-12 ${tone}`} />
        <div className="flex-1 min-w-0">
          <div className="text-xs uppercase tracking-widest text-muted-foreground">Sender domain · {(r.durationMs / 1000).toFixed(1)}s</div>
          <div className="font-mono text-sm truncate">{r.from ?? r.host}</div>
          <div className="mt-2 flex items-center gap-3 flex-wrap">
            <SeverityBadge level={r.verdict} />
            <span className="text-xs text-muted-foreground">Category: <span className="text-foreground">{r.category}</span></span>
            {r.subject && <span className="text-xs text-muted-foreground truncate">Subject: {r.subject}</span>}
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Metric label="Threat" value={r.threatScore} className={tone} />
          <Metric label="Security" value={r.securityScore} className="text-safe" />
          <Metric label="Attack Prob." value={`${r.attackProbability}%`} className="text-high" />
          <Metric label="Confidence" value={`${r.confidence}%`} className="neon-text" />
        </div>
      </div>

      {r.explanation && (
        <div className="glass rounded-lg p-5">
          <SectionHeader title="AI Explanation" subtitle="Written from this email's own evidence" />
          <p className="text-sm leading-relaxed">{r.explanation}</p>
        </div>
      )}

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="glass rounded-lg p-5">
          <SectionHeader title="Authentication (SPF · DKIM · DMARC)" subtitle="The three records that prove a sender is genuine" />
          <dl className="text-xs space-y-2">
            {[["SPF", r.auth.spf], ["DKIM", r.auth.dkim], ["DMARC", r.auth.dmarc], ["Alignment", r.auth.alignment],
              ["SPF record", r.records.spf ?? "none published"], ["DMARC record", r.records.dmarc ?? "none published"],
              ["MX", r.records.mx.join(", ") || "none"], ["Return-Path", r.returnPath ?? "—"], ["Reply-To", r.replyTo ?? "—"]].map(([k, v]) => (
              <div key={k as string} className="flex justify-between gap-3 border-b border-border/40 pb-1.5">
                <dt className="text-muted-foreground uppercase tracking-wider text-[10px]">{k}</dt>
                <dd className="font-mono truncate max-w-[62%] text-right">{v as string}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="glass rounded-lg p-5">
          <SectionHeader title="Feature Attribution" subtitle="How much each finding pushed the score" />
          <div className="space-y-3">
            {r.signals.map((s) => (
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
      </div>

      <div className="glass rounded-lg p-5">
        <SectionHeader title="Links Found Inside the Email" subtitle="Each link checked against Safe Browsing, URLHaus, VirusTotal and AbuseIPDB" right={<Link2 className="h-4 w-4 text-muted-foreground" />} />
        {!r.urls.length ? (
          <div className="text-xs text-muted-foreground">No links found in the message body.</div>
        ) : (
          <div className="space-y-3">
            {r.urls.map((u) => (
              <div key={u.url} className="rounded border border-border/60 p-3">
                <div className="flex items-center justify-between gap-3 mb-2">
                  <span className="font-mono text-xs truncate">{u.url}</span>
                  <SeverityBadge level={u.verdict} />
                </div>
                <div className="text-[11px] text-muted-foreground mb-2">Host {u.host} · IP {u.ip ?? "unresolved"}</div>
                <div className="grid sm:grid-cols-2 gap-1.5">
                  {u.sources.map((s) => (
                    <div key={s.source} className="flex justify-between text-[11px] bg-secondary/40 rounded px-2 py-1">
                      <span>{s.source}</span>
                      <span className={s.hits > 0 ? "text-critical" : "text-muted-foreground"}>{s.verdict}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="glass rounded-lg p-5">
          <SectionHeader title="Checks" />
          <table className="w-full text-xs">
            <tbody>
              {r.vulns.map((v) => (
                <tr key={v.name} className="border-b border-border/30 align-top">
                  <td className="py-2 font-medium">{v.name}</td>
                  <td><SeverityBadge level={v.status} /></td>
                  <td className="text-muted-foreground">{v.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="glass rounded-lg p-5">
          <SectionHeader title="Recommended Actions" />
          <ul className="space-y-2 text-sm">
            {r.recommendations.map((rec, i) => (
              <li key={i} className="flex gap-3">
                <span className="h-6 w-6 shrink-0 rounded-full bg-secondary flex items-center justify-center text-xs font-bold">{i + 1}</span>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
          {r.hops.length > 0 && (
            <>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-4 mb-2">Received chain (mail hops)</div>
              <ol className="space-y-1 text-[11px] font-mono text-muted-foreground">
                {r.hops.map((h, i) => <li key={i} className="truncate">{h}</li>)}
              </ol>
            </>
          )}
        </div>
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
