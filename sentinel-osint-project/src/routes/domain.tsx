import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader, SeverityBadge } from "@/components/ui-bits";
import { useState } from "react";
import { Search, Globe, Shield, Server, Loader2 } from "lucide-react";

export const Route = createFileRoute("/domain")({
  head: () => ({
    meta: [
      { title: "Domain Intelligence — Sentinel OSINT" },
      { name: "description", content: "WHOIS, DNS, ASN, SSL, reputation, and hosting intelligence for any domain." },
    ],
  }),
  component: () => <AppShell><Domain /></AppShell>,
});

function Domain() {
  const [q, setQ] = useState("");
  const [d, setD] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    if (!q) return;
    setLoading(true); setD(null);
    await new Promise(r => setTimeout(r, 700));
    setD(q); setLoading(false);
  };
  return (
    <>
      <PageHeader kicker="OSINT" title="Domain Intelligence" subtitle="WHOIS, DNS, ASN, SSL, hosting country, blacklist status." />
      <div className="glass rounded-lg p-4 mb-6 flex gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="example.com"
            className="w-full pl-10 pr-4 py-2 rounded-md bg-input border border-border font-mono text-sm" />
        </div>
        <button onClick={run} className="px-5 py-2 rounded-md bg-primary text-primary-foreground text-xs font-bold uppercase tracking-widest neon-border">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Lookup"}
        </button>
      </div>

      {d && (
        <div className="grid md:grid-cols-3 gap-4">
          <Card icon={<Globe className="h-5 w-5" />} title="WHOIS">
            <Row k="Registrar" v="NameCheap Inc." />
            <Row k="Registered" v="2024-01-14" />
            <Row k="Expires" v="2028-01-14" />
            <Row k="Registrant" v="REDACTED FOR PRIVACY" />
            <Row k="Domain Age" v="581 days" />
          </Card>
          <Card icon={<Server className="h-5 w-5" />} title="DNS / ASN">
            <Row k="A Record" v="104.21.32.14" />
            <Row k="Name Servers" v="ns1.cloudflare.com" />
            <Row k="ASN" v="AS13335 Cloudflare" />
            <Row k="Country" v="United States" />
            <Row k="MX Records" v="alt1.gmail.com" />
          </Card>
          <Card icon={<Shield className="h-5 w-5" />} title="Security">
            <Row k="SSL Issuer" v="Let's Encrypt R3" />
            <Row k="TLS" v="1.3" />
            <Row k="DNSSEC" v="Enabled" />
            <Row k="Blacklist" v={<SeverityBadge level="safe">Clean</SeverityBadge>} />
            <Row k="Risk Score" v="12 / 100" />
          </Card>
        </div>
      )}
    </>
  );
}

function Card({ icon, title, children }: any) {
  return (
    <div className="glass rounded-lg p-5">
      <SectionHeader title={title} right={<div className="text-primary">{icon}</div>} />
      <dl className="text-xs space-y-2">{children}</dl>
    </div>
  );
}
function Row({ k, v }: { k: string; v: any }) {
  return (
    <div className="flex justify-between gap-3 border-b border-border/40 pb-1.5">
      <dt className="text-muted-foreground uppercase tracking-wider text-[10px]">{k}</dt>
      <dd className="font-mono text-right">{v}</dd>
    </div>
  );
}
