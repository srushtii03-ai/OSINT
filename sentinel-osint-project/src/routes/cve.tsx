import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SeverityBadge } from "@/components/ui-bits";
import { cves } from "@/lib/mock-data";
import { useState } from "react";
import { Search, ExternalLink } from "lucide-react";

export const Route = createFileRoute("/cve")({
  head: () => ({
    meta: [
      { title: "CVE Database — Sentinel OSINT" },
      { name: "description", content: "Search the latest CVEs, CVSS scores, and known-exploited vulnerabilities from NVD and CISA KEV." },
    ],
  }),
  component: () => <AppShell><CVE /></AppShell>,
});

function CVE() {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string>("all");
  const filtered = cves.filter(c => {
    const okQ = !q || (c.id + c.product + c.desc).toLowerCase().includes(q.toLowerCase());
    const okS = sev === "all" || c.severity === sev;
    return okQ && okS;
  });
  return (
    <>
      <PageHeader kicker="Vulnerability Intelligence" title="CVE Database" subtitle="NVD · CISA KEV · Exploit-DB fusion. Updated every 5 minutes." />
      <div className="glass rounded-lg p-4 mb-6 flex flex-wrap gap-3">
        <div className="flex-1 relative min-w-[240px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search CVE ID, product, keyword..."
            className="w-full pl-10 pr-4 py-2 rounded-md bg-input border border-border text-sm outline-none focus:neon-border" />
        </div>
        <select value={sev} onChange={e => setSev(e.target.value)} className="px-3 py-2 rounded-md bg-input border border-border text-sm">
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="space-y-3">
        {filtered.map(c => (
          <div key={c.id} className="glass rounded-lg p-5 hover:neon-border transition">
            <div className="flex flex-wrap items-start justify-between gap-3 mb-2">
              <div>
                <div className="flex items-center gap-3 mb-1">
                  <span className="font-mono text-primary font-bold">{c.id}</span>
                  <SeverityBadge level={c.severity} />
                  {c.exploit && <SeverityBadge level="critical" className="!bg-critical/30">Exploit ITW</SeverityBadge>}
                </div>
                <div className="font-bold">{c.product}</div>
              </div>
              <div className="text-right">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">CVSS</div>
                <div className="text-2xl font-bold neon-text">{c.cvss}</div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground">{c.desc}</p>
            <div className="mt-3 flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Published {c.published}</span>
              <a className="text-primary flex items-center gap-1 hover:underline" href="#">Full advisory <ExternalLink className="h-3 w-3" /></a>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
