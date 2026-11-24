import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader, SeverityBadge } from "@/components/ui-bits";
import { useState } from "react";
import { Search, MapPin, AlertTriangle, Loader2 } from "lucide-react";

export const Route = createFileRoute("/ip")({
  head: () => ({
    meta: [
      { title: "IP Intelligence — Sentinel OSINT" },
      { name: "description", content: "Geolocation, ASN, open ports, abuse reports, and threat score for any IP address." },
    ],
  }),
  component: () => <AppShell><IP /></AppShell>,
});

function IP() {
  const [q, setQ] = useState("");
  const [ip, setIp] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { if (!q) return; setLoading(true); setIp(null); await new Promise(r=>setTimeout(r,700)); setIp(q); setLoading(false); };
  return (
    <>
      <PageHeader kicker="OSINT" title="IP Intelligence" subtitle="Shodan · Censys · AbuseIPDB · GreyNoise fusion." />
      <div className="glass rounded-lg p-4 mb-6 flex gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="185.220.101.42"
            className="w-full pl-10 pr-4 py-2 rounded-md bg-input border border-border font-mono text-sm" />
        </div>
        <button onClick={run} className="px-5 py-2 rounded-md bg-primary text-primary-foreground text-xs font-bold uppercase tracking-widest neon-border">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Lookup"}
        </button>
      </div>
      {ip && (
        <div className="grid md:grid-cols-3 gap-4">
          <div className="glass rounded-lg p-5 md:col-span-1">
            <SectionHeader title="Geolocation" right={<MapPin className="h-4 w-4 text-primary" />} />
            <div className="text-3xl font-bold neon-text">RU</div>
            <div className="text-sm mt-1">Saint Petersburg</div>
            <div className="text-xs text-muted-foreground mt-4 space-y-1">
              <div>ISP: Bulletproof Hosting Ltd.</div>
              <div>ASN: AS41564</div>
              <div>Coordinates: 59.93°N 30.31°E</div>
              <div>Reverse DNS: tor-exit-42.bph.net</div>
            </div>
          </div>
          <div className="glass rounded-lg p-5">
            <SectionHeader title="Threat Assessment" right={<AlertTriangle className="h-4 w-4 text-critical" />} />
            <div className="text-4xl font-bold text-critical">92</div>
            <div className="text-xs text-muted-foreground">/ 100 threat score</div>
            <div className="mt-4 space-y-2 text-xs">
              <div className="flex justify-between"><span>Abuse reports</span><span className="text-critical">342</span></div>
              <div className="flex justify-between"><span>GreyNoise class</span><SeverityBadge level="critical">malicious</SeverityBadge></div>
              <div className="flex justify-between"><span>Tor exit node</span><span className="text-medium">Yes</span></div>
              <div className="flex justify-between"><span>Known C2</span><span className="text-critical">Emotet</span></div>
            </div>
          </div>
          <div className="glass rounded-lg p-5">
            <SectionHeader title="Open Ports" />
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                {p: 22, s: "SSH · OpenSSH 8.2"},
                {p: 80, s: "HTTP · nginx 1.18"},
                {p: 443, s: "HTTPS · nginx 1.18"},
                {p: 3389, s: "RDP"},
                {p: 8080, s: "HTTP-alt"},
                {p: 9001, s: "Tor OR"},
              ].map(x => (
                <div key={x.p} className="p-2 rounded bg-secondary/40 border border-border">
                  <div className="font-mono font-bold text-primary">:{x.p}</div>
                  <div className="text-muted-foreground text-[10px]">{x.s}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
