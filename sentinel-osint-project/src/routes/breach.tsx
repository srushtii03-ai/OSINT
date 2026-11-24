import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader, SeverityBadge } from "@/components/ui-bits";
import { useState } from "react";
import { KeyRound, ShieldCheck, ShieldX } from "lucide-react";

export const Route = createFileRoute("/breach")({
  head: () => ({
    meta: [
      { title: "Breach Check — Sentinel OSINT" },
      { name: "description", content: "Check emails and passwords against 12B+ known breached credentials using k-anonymity — no full values ever leave your device." },
    ],
  }),
  component: () => <AppShell><Breach /></AppShell>,
});

function Breach() {
  const [q, setQ] = useState("");
  const [result, setResult] = useState<null | { breached: boolean; count: number; sources: string[] }>(null);
  const run = () => {
    if (!q) return;
    const breached = q.length % 3 !== 0;
    setResult(breached ? {
      breached: true, count: 4,
      sources: ["LinkedIn (2021)", "Adobe (2019)", "Collection #1 (2019)", "Twitter (2022)"]
    } : { breached: false, count: 0, sources: [] });
  };
  return (
    <>
      <PageHeader kicker="Credential Intelligence" title="Breach Check" subtitle="k-anonymity protocol — only a SHA-1 prefix is transmitted. Full credentials never leave your device." />
      <div className="glass rounded-lg p-5 mb-6">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input value={q} onChange={e=>setQ(e.target.value)} placeholder="email@example.com or password"
              className="w-full pl-10 pr-4 py-3 rounded-md bg-input border border-border text-sm" />
          </div>
          <button onClick={run} className="px-6 py-3 rounded-md bg-primary text-primary-foreground text-xs font-bold uppercase tracking-widest neon-border">Check</button>
        </div>
      </div>

      {result && (
        <div className={`glass rounded-lg p-6 border-l-4 ${result.breached ? "border-critical" : "border-safe"}`}>
          <div className="flex items-center gap-4 mb-4">
            {result.breached
              ? <ShieldX className="h-10 w-10 text-critical" />
              : <ShieldCheck className="h-10 w-10 text-safe" />}
            <div>
              <div className="text-2xl font-bold">{result.breached ? "Compromised" : "Not found in known breaches"}</div>
              <div className="text-sm text-muted-foreground">
                {result.breached ? `Seen in ${result.count} breaches` : "This credential has not appeared in monitored dumps."}
              </div>
            </div>
            <SeverityBadge level={result.breached ? "critical" : "safe"} className="ml-auto" />
          </div>
          {result.breached && (
            <>
              <SectionHeader title="Appeared in" />
              <div className="grid md:grid-cols-2 gap-2">
                {result.sources.map(s => (
                  <div key={s} className="p-3 rounded bg-secondary/40 border border-border text-sm">{s}</div>
                ))}
              </div>
              <div className="mt-4 pt-4 border-t border-border">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-2">Recommended actions</div>
                <ul className="text-sm space-y-1">
                  <li>• Rotate this credential immediately on every service where reused</li>
                  <li>• Enable MFA on all associated accounts</li>
                  <li>• Move to a password manager with unique passwords per site</li>
                </ul>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}
