import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Shield, Radar, Brain, Globe2, Lock, Zap, Eye, Bug, Chrome, ArrowRight,
  CheckCircle2, Activity, Cpu, Database, Sparkles
} from "lucide-react";
import { AttackMap } from "@/components/attack-map";
import { threatStats, topActors } from "@/lib/mock-data";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Sentinel OSINT — AI Threat Intelligence Platform" },
      { name: "description", content: "Enterprise AI-powered OSINT threat intelligence: URL security analysis, vulnerability detection, browser protection, explainable AI, and a live global attack feed." },
      { property: "og:title", content: "Sentinel OSINT — AI Threat Intelligence" },
      { property: "og:description", content: "Detect phishing, malware, C2, and zero-days before they reach your users. Powered by 16 OSINT sources and explainable AI." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Landing,
});

function Landing() {
  return (
    <div className="min-h-screen">
      {/* Nav */}
      <header className="sticky top-0 z-40 glass border-b border-border/60">
        <div className="max-w-7xl mx-auto flex items-center gap-6 px-4 h-16">
          <Link to="/" className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-bold tracking-wider">SENTINEL/OSINT</span>
          </Link>
          <nav className="hidden md:flex items-center gap-6 text-xs uppercase tracking-widest text-muted-foreground">
            <a href="#features" className="hover:text-foreground">Features</a>
            <a href="#how" className="hover:text-foreground">How AI Works</a>
            <a href="#sources" className="hover:text-foreground">Sources</a>
            <a href="#stack" className="hover:text-foreground">Stack</a>
            <a href="#faq" className="hover:text-foreground">FAQ</a>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <Link to="/scanner" className="text-xs px-3 py-2 rounded-md hover:bg-secondary">Try scanner</Link>
            <Link to="/dashboard" className="text-xs px-4 py-2 rounded-md bg-primary text-primary-foreground neon-border font-bold uppercase tracking-widest">
              Open SOC
            </Link>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 pt-16 pb-24 grid lg:grid-cols-2 gap-10 items-center">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass text-[10px] uppercase tracking-[0.25em] mb-6">
              <span className="h-1.5 w-1.5 rounded-full bg-safe animate-flicker" />
              Live · 16 OSINT sources connected
            </div>
            <h1 className="text-4xl md:text-6xl font-black tracking-tight leading-[1.05]">
              Detect threats <span className="neon-text">before</span><br />
              the attack begins.
            </h1>
            <p className="mt-5 text-muted-foreground max-w-lg leading-relaxed">
              Sentinel fuses 16 global OSINT feeds with explainable AI to score URLs,
              domains, IPs, files, and email — in under 400ms. Built for SOC teams,
              researchers, and organizations that can't afford to be surprised.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link to="/scanner" className="inline-flex items-center gap-2 px-5 py-3 rounded-md bg-primary text-primary-foreground font-bold uppercase tracking-widest text-xs neon-border">
                Scan a URL <ArrowRight className="h-4 w-4" />
              </Link>
              <Link to="/dashboard" className="inline-flex items-center gap-2 px-5 py-3 rounded-md border border-border font-bold uppercase tracking-widest text-xs hover:bg-secondary">
                Enter SOC Dashboard
              </Link>
            </div>
            <div className="mt-10 grid grid-cols-3 gap-4 max-w-md">
              {[
                { label: "Scans today", value: threatStats.totalScans.toLocaleString() },
                { label: "Blocked", value: threatStats.blockedToday.toLocaleString() },
                { label: "Assets", value: threatStats.monitoredAssets.toLocaleString() },
              ].map(s => (
                <div key={s.label}>
                  <div className="text-2xl font-bold neon-text">{s.value}</div>
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{s.label}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="relative aspect-[4/3] lg:h-[520px]">
            <AttackMap />
          </div>
        </div>
      </section>

      {/* Feature grid */}
      <section id="features" className="py-20 border-t border-border/60">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-12">
            <div className="text-[10px] uppercase tracking-[0.25em] text-primary mb-2">Capabilities</div>
            <h2 className="text-3xl md:text-4xl font-bold">Everything your SOC needs, in one platform.</h2>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {FEATURES.map(f => (
              <div key={f.title} className="glass rounded-lg p-6 group hover:neon-border transition">
                <f.icon className="h-6 w-6 text-primary mb-4" />
                <h3 className="font-bold mb-1">{f.title}</h3>
                <p className="text-sm text-muted-foreground">{f.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How AI works */}
      <section id="how" className="py-20 border-t border-border/60">
        <div className="max-w-7xl mx-auto px-4 grid lg:grid-cols-2 gap-10 items-center">
          <div>
            <div className="text-[10px] uppercase tracking-[0.25em] text-primary mb-2">Explainable AI</div>
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Every verdict shows its <span className="neon-text">reasoning</span>.
            </h2>
            <p className="text-muted-foreground mb-6">
              Sentinel uses SHAP-based explainability on top of a transformer URL classifier
              and gradient-boosted feature model. Analysts see exactly which signals pushed a
              verdict — never a black box.
            </p>
            <ul className="space-y-3">
              {[
                "Transformer URL classifier fine-tuned on 42M labeled samples",
                "Gradient-boosted domain feature model with 128 engineered features",
                "SHAP values surface top contributing signals per prediction",
                "Confidence calibrated with isotonic regression",
              ].map(x => (
                <li key={x} className="flex gap-2 text-sm">
                  <CheckCircle2 className="h-4 w-4 text-safe shrink-0 mt-0.5" /> {x}
                </li>
              ))}
            </ul>
          </div>
          <div className="glass rounded-lg p-6">
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-4">SHAP Feature Attribution — Example</div>
            <div className="space-y-3">
              {[
                { name: "Domain Age (3 days)", weight: 92, dir: "risk" },
                { name: "Brand keyword: 'paypal'", weight: 78, dir: "risk" },
                { name: "TLS: Let's Encrypt, 2h old", weight: 64, dir: "risk" },
                { name: "URL entropy score", weight: 51, dir: "risk" },
                { name: "Hosted on VPN/bulletproof ASN", weight: 44, dir: "risk" },
                { name: "Global reputation", weight: 22, dir: "safe" },
              ].map(s => (
                <div key={s.name}>
                  <div className="flex justify-between text-xs mb-1">
                    <span>{s.name}</span>
                    <span className={s.dir === "risk" ? "text-critical" : "text-safe"}>{s.dir === "risk" ? "+" : "−"}{s.weight}</span>
                  </div>
                  <div className="h-2 rounded bg-secondary overflow-hidden">
                    <div className={`h-full ${s.dir === "risk" ? "bg-critical" : "bg-safe"}`} style={{ width: `${s.weight}%` }} />
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-6 pt-4 border-t border-border flex items-center justify-between">
              <div>
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Verdict</div>
                <div className="text-2xl font-bold text-critical">MALICIOUS</div>
              </div>
              <div className="text-right">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Confidence</div>
                <div className="text-2xl font-bold neon-text">96%</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Sources */}
      <section id="sources" className="py-20 border-t border-border/60">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-10">
            <div className="text-[10px] uppercase tracking-[0.25em] text-primary mb-2">OSINT Fusion</div>
            <h2 className="text-3xl md:text-4xl font-bold">16 sources, one verdict.</h2>
          </div>
          <div className="flex flex-wrap justify-center gap-2">
            {[
              "VirusTotal","Google Safe Browsing","AbuseIPDB","AlienVault OTX","Shodan","Censys",
              "ThreatFox","URLHaus","PhishTank","GreyNoise","SecurityTrails","NVD","MITRE ATT&CK",
              "CISA KEV","Hybrid Analysis","OpenPhish"
            ].map(s => (
              <div key={s} className="px-4 py-2 rounded-md glass text-xs">{s}</div>
            ))}
          </div>
        </div>
      </section>

      {/* Stack */}
      <section id="stack" className="py-20 border-t border-border/60">
        <div className="max-w-7xl mx-auto px-4 grid md:grid-cols-3 gap-6">
          <div className="glass rounded-lg p-6">
            <Cpu className="h-6 w-6 text-primary mb-3" />
            <h3 className="font-bold mb-2">Detection Engine</h3>
            <p className="text-sm text-muted-foreground">Transformer + XGBoost ensemble, SHAP explainability, sub-400ms inference at the edge.</p>
          </div>
          <div className="glass rounded-lg p-6">
            <Database className="h-6 w-6 text-primary mb-3" />
            <h3 className="font-bold mb-2">Threat Warehouse</h3>
            <p className="text-sm text-muted-foreground">Continuously ingests 16 OSINT feeds into a normalized IOC graph with lineage tracking.</p>
          </div>
          <div className="glass rounded-lg p-6">
            <Activity className="h-6 w-6 text-primary mb-3" />
            <h3 className="font-bold mb-2">Live Streaming</h3>
            <p className="text-sm text-muted-foreground">WebSocket-driven SOC dashboards with sub-second alerting and configurable playbooks.</p>
          </div>
        </div>
      </section>

      {/* Actors */}
      <section className="py-20 border-t border-border/60">
        <div className="max-w-7xl mx-auto px-4">
          <div className="mb-8">
            <div className="text-[10px] uppercase tracking-[0.25em] text-primary mb-2">Adversary Intelligence</div>
            <h2 className="text-3xl md:text-4xl font-bold">Tracked threat actors</h2>
          </div>
          <div className="grid md:grid-cols-5 gap-3">
            {topActors.map(a => (
              <div key={a.name} className="glass rounded-lg p-4">
                <div className="text-xs text-muted-foreground">{a.origin}</div>
                <div className="font-bold mt-1">{a.name}</div>
                <div className="text-xs text-primary mt-2">{a.campaigns} active campaigns</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="py-20 border-t border-border/60">
        <div className="max-w-4xl mx-auto px-4">
          <div className="text-center mb-10">
            <div className="text-[10px] uppercase tracking-[0.25em] text-primary mb-2">FAQ</div>
            <h2 className="text-3xl md:text-4xl font-bold">Common questions</h2>
          </div>
          <div className="space-y-3">
            {FAQ.map((q, i) => (
              <details key={i} className="glass rounded-lg p-5 group">
                <summary className="cursor-pointer font-semibold flex items-center justify-between">
                  {q.q}
                  <ArrowRight className="h-4 w-4 transition group-open:rotate-90" />
                </summary>
                <p className="mt-3 text-sm text-muted-foreground">{q.a}</p>
              </details>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 border-t border-border/60">
        <div className="max-w-4xl mx-auto px-4 text-center">
          <Sparkles className="h-8 w-8 text-primary mx-auto mb-4" />
          <h2 className="text-3xl md:text-5xl font-bold mb-4">Stop reacting. Start seeing.</h2>
          <p className="text-muted-foreground mb-8">Deploy Sentinel and get a live threat picture in under 10 minutes.</p>
          <Link to="/dashboard" className="inline-flex items-center gap-2 px-6 py-4 rounded-md bg-primary text-primary-foreground font-bold uppercase tracking-widest text-sm neon-border">
            Enter the SOC <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>

      <footer className="border-t border-border/60 py-10">
        <div className="max-w-7xl mx-auto px-4 flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" /> SENTINEL/OSINT · Threat Intelligence
          </div>
          <div>© 2026 · Enterprise Security Platform · SOC 2 · ISO 27001</div>
        </div>
      </footer>
    </div>
  );
}

const FEATURES = [
  { icon: Radar, title: "AI URL Security Checker", body: "Phishing, malware, typosquatting, homograph, C2, credential harvesting — all in one verdict." },
  { icon: Bug, title: "Vulnerability Analysis", body: "SSL, TLS, security headers, cookies, open ports, CMS, JS libs, known CVEs, OWASP Top 10." },
  { icon: Brain, title: "Explainable AI", body: "SHAP-driven attribution shows exactly why the model predicted malicious." },
  { icon: Globe2, title: "Live Attack Map", body: "Real-time global feed of attack origins, targets, and campaigns." },
  { icon: Lock, title: "Breach Intelligence", body: "Check emails and password hashes against 12B+ known breached credentials." },
  { icon: Eye, title: "Domain & IP Intel", body: "WHOIS, DNS, ASN, geolocation, blacklists, reputation, and hosting country." },
  { icon: Chrome, title: "Browser Extension", body: "Real-time page protection with safe/warning/danger overlays." },
  { icon: Zap, title: "AI Analyst Chatbot", body: "Ask about CVEs, IOCs, ATT&CK techniques, or generate incident reports." },
  { icon: Activity, title: "SOC Dashboard", body: "Critical alerts, threat timeline, attack heatmaps, latest CVEs and IOCs." },
];

const FAQ = [
  { q: "Which OSINT sources are integrated?", a: "16 including VirusTotal, Google Safe Browsing, AbuseIPDB, AlienVault OTX, Shodan, Censys, ThreatFox, URLHaus, PhishTank, GreyNoise, SecurityTrails, NVD, MITRE ATT&CK, CISA KEV, Hybrid Analysis, and OpenPhish." },
  { q: "How does the AI decide something is malicious?", a: "A transformer URL classifier and a gradient-boosted feature model each produce a score. Their outputs are fused and calibrated. SHAP values show which features drove the verdict, so analysts see reasoning — not a black box." },
  { q: "Can I run this on-premise?", a: "Yes. Sentinel ships as Docker Compose and can be deployed to any Kubernetes cluster. All threat intelligence caching happens locally in Redis + MongoDB." },
  { q: "Do you store user passwords for breach checks?", a: "Never. Password checks use k-anonymity — only a 5-character SHA-1 prefix is transmitted, matching Have I Been Pwned's protocol." },
  { q: "What roles are supported?", a: "Admin, SOC Analyst, Researcher, Student, and Viewer. Access is enforced with JWT + RBAC on every endpoint." },
];
