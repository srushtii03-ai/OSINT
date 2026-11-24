import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader } from "@/components/ui-bits";
import { useState } from "react";
import { Send, Bot, User } from "lucide-react";

export const Route = createFileRoute("/chat")({
  head: () => ({
    meta: [
      { title: "AI Analyst — Sentinel OSINT" },
      { name: "description", content: "Ask an AI cybersecurity analyst about URLs, domains, CVEs, MITRE ATT&CK, and generate incident reports." },
    ],
  }),
  component: () => <AppShell><Chat /></AppShell>,
});

const canned: Record<string, string> = {
  default: "I'm Sentinel — your OSINT analyst. Ask me about a URL, IP, CVE, MITRE ATT&CK technique, or ask me to draft an incident report.",
  cve: "CVE-2026-2489 is a critical unauthenticated RCE in VMware vCenter's SOAP endpoint (CVSS 9.9). Exploitation is trivial and observed in the wild. Immediate mitigation: block port 443 to vCenter from untrusted networks, apply KB-2026-089, and hunt for anomalous SOAP requests in vpxd.log.",
  phishing: "Phishing detection combines: (1) URL entropy + brand keyword match, (2) domain age and WHOIS reputation, (3) SSL issuer + certificate age, (4) content-level transformer classifier, (5) live checks against PhishTank, OpenPhish, and Google Safe Browsing. SHAP surfaces the top drivers for each verdict.",
  incident: "Incident Report — DRAFT\n\nSummary: On 2026-07-24 at 14:22 UTC, 7 endpoints beaconed to 185.220.101.42 (known Emotet C2). Initial vector: phishing email impersonating PayPal, delivered to finance team.\n\nContainment: Isolated hosts, rotated credentials, blocked IOC at perimeter.\n\nRecommendations: Enable attachment sandboxing, deploy Sentinel browser extension org-wide, run tabletop exercise for phishing scenarios.",
};

function guess(q: string): string {
  const s = q.toLowerCase();
  if (s.includes("cve")) return canned.cve;
  if (s.includes("phishing") || s.includes("phish")) return canned.phishing;
  if (s.includes("incident") || s.includes("report")) return canned.incident;
  return "Based on current OSINT feeds and the AI model, here's a summary: " +
    "the indicator you provided shows moderate risk. I'd correlate against your SIEM for related activity in the last 30 days, and check whether any user credentials appear in recent breach dumps.";
}

function Chat() {
  const [msgs, setMsgs] = useState<{ role: "user" | "bot"; text: string }[]>([
    { role: "bot", text: canned.default },
  ]);
  const [input, setInput] = useState("");
  const send = () => {
    if (!input.trim()) return;
    const u = input;
    setMsgs(m => [...m, { role: "user", text: u }]);
    setInput("");
    setTimeout(() => setMsgs(m => [...m, { role: "bot", text: guess(u) }]), 400);
  };
  return (
    <>
      <PageHeader kicker="AI Analyst" title="Cybersecurity Assistant" subtitle="Explain URLs, CVEs, MITRE ATT&CK techniques, or draft an incident report." />
      <div className="glass rounded-lg flex flex-col h-[70vh]">
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {msgs.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === "user" ? "flex-row-reverse" : ""}`}>
              <div className={`h-8 w-8 rounded-full flex items-center justify-center shrink-0 ${m.role === "user" ? "bg-cyber/30 text-cyber" : "bg-primary/30 text-primary"}`}>
                {m.role === "user" ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
              </div>
              <div className={`max-w-[75%] p-3 rounded-lg text-sm whitespace-pre-wrap ${m.role === "user" ? "bg-cyber/15 border border-cyber/40" : "bg-secondary/60 border border-border"}`}>
                {m.text}
              </div>
            </div>
          ))}
        </div>
        <div className="border-t border-border p-3 flex gap-2">
          <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e => e.key==="Enter" && send()}
            placeholder="Ask about a CVE, URL, IP, or 'draft incident report'..."
            className="flex-1 px-4 py-2 rounded-md bg-input border border-border text-sm" />
          <button onClick={send} className="px-4 py-2 rounded-md bg-primary text-primary-foreground neon-border flex items-center gap-2 text-xs font-bold uppercase tracking-widest">
            <Send className="h-4 w-4" /> Send
          </button>
        </div>
      </div>
      <div className="mt-4 grid md:grid-cols-3 gap-3 text-xs">
        {["Explain CVE-2026-2489","How does phishing detection work?","Draft an incident report for Emotet C2 beaconing"].map(s => (
          <button key={s} onClick={() => { setInput(s); setTimeout(send, 0); }} className="glass p-3 rounded-md text-left hover:neon-border">
            {s}
          </button>
        ))}
      </div>
    </>
  );
}
