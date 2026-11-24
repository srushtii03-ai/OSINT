import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader } from "@/components/ui-bits";
import { Chrome, ShieldCheck, ShieldAlert, ShieldX, Download } from "lucide-react";

export const Route = createFileRoute("/extension")({
  head: () => ({
    meta: [
      { title: "Browser Extension — Sentinel OSINT" },
      { name: "description", content: "Chrome and Edge extension that scans every URL and shows safe / warning / danger overlays with AI reasoning." },
    ],
  }),
  component: () => <AppShell><Ext /></AppShell>,
});

function Ext() {
  return (
    <>
      <PageHeader kicker="Endpoint" title="Browser Protection Extension" subtitle="Real-time page-level protection powered by the Sentinel AI engine." />
      <div className="grid lg:grid-cols-2 gap-4">
        <div className="glass rounded-lg p-6">
          <Chrome className="h-8 w-8 text-primary mb-3" />
          <h3 className="font-bold text-lg mb-2">Sentinel for Chrome & Edge</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Automatically scans every URL you open. Uses the same AI + OSINT engine as the SOC dashboard.
          </p>
          <button className="inline-flex items-center gap-2 px-5 py-3 rounded-md bg-primary text-primary-foreground text-xs font-bold uppercase tracking-widest neon-border">
            <Download className="h-4 w-4" /> Download .zip
          </button>
          <div className="mt-6 pt-6 border-t border-border">
            <SectionHeader title="Install" />
            <ol className="text-xs space-y-2 list-decimal pl-4 text-muted-foreground">
              <li>Download and unzip the extension bundle</li>
              <li>Open chrome://extensions and enable Developer Mode</li>
              <li>Click "Load unpacked" and select the unzipped folder</li>
              <li>Pin Sentinel to the toolbar for one-click scans</li>
            </ol>
          </div>
        </div>

        <div className="space-y-3">
          <SectionHeader title="Popup preview" />
          {[
            { verdict: "SAFE", tone: "safe", Icon: ShieldCheck, url: "https://github.com", reason: "Domain age 15y · Global reputation high · No IOC matches" },
            { verdict: "WARNING", tone: "medium", Icon: ShieldAlert, url: "https://bit.ly/xR2p9", reason: "Shortened URL · Redirect chain ends on newly-registered domain (3 days)" },
            { verdict: "DANGER", tone: "critical", Icon: ShieldX, url: "https://paypa1-verify-login.com", reason: "Typosquat of paypal.com · Listed on PhishTank · TLS cert 4h old" },
          ].map((p) => (
            <div key={p.verdict} className={`glass rounded-lg p-4 border-l-4 border-${p.tone}`}>
              <div className="flex items-center gap-3">
                <p.Icon className={`h-8 w-8 text-${p.tone}`} />
                <div className="flex-1 min-w-0">
                  <div className={`text-xs font-bold uppercase tracking-widest text-${p.tone}`}>{p.verdict}</div>
                  <div className="font-mono text-xs truncate">{p.url}</div>
                </div>
                <div className={`text-2xl font-bold text-${p.tone}`}>{p.verdict === "SAFE" ? "6" : p.verdict === "WARNING" ? "58" : "94"}</div>
              </div>
              <div className="mt-2 text-xs text-muted-foreground">{p.reason}</div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
