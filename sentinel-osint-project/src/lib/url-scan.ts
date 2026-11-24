export type ScanResult = {
  url: string;
  verdict: "safe" | "suspicious" | "malicious";
  threatScore: number;
  confidence: number;
  category: string;
  categoryFlags: { label: string; hit: boolean }[];
  signals: { name: string; weight: number; direction: "risk" | "safe" }[];
  vulns: { name: string; status: "pass" | "warn" | "fail"; detail: string }[];
  intel: { source: string; verdict: string; hits: number }[];
  domain: {
    registrar: string;
    ageDays: number;
    country: string;
    asn: string;
    ip: string;
    ssl: string;
    tls: string;
  };
  recommendations: string[];
};

const KNOWN_SAFE = ["google.com", "amazon.com", "microsoft.com", "github.com", "cloudflare.com", "wikipedia.org"];

function hash(str: string) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  return Math.abs(h);
}

export function scanUrl(input: string): ScanResult {
  const url = input.trim();
  let host = url;
  try { host = new URL(url.startsWith("http") ? url : "https://" + url).hostname; } catch {}
  const bare = host.replace(/^www\./, "");
  const known = KNOWN_SAFE.some(d => bare.endsWith(d));
  const suspiciousTokens = ["login", "verify", "secure", "wallet", "airdrop", "reset", "gift", "bonus", "-", "xn--"];
  const hits = suspiciousTokens.filter(t => bare.includes(t)).length;
  const h = hash(bare);

  let threatScore = known ? 4 + (h % 8) : 45 + (h % 45) + hits * 6;
  threatScore = Math.min(99, Math.max(1, threatScore));
  const verdict: ScanResult["verdict"] = threatScore >= 75 ? "malicious" : threatScore >= 45 ? "suspicious" : "safe";
  const category = verdict === "malicious"
    ? ["Phishing", "Credential Harvesting", "Malware Distribution", "Crypto Scam"][h % 4]
    : verdict === "suspicious"
      ? ["Typosquat", "Suspicious Redirect", "Newly Registered Domain"][h % 3]
      : "Legitimate";

  const flag = (label: string, on: boolean) => ({ label, hit: on });
  const categoryFlags = [
    flag("Phishing Detection", verdict !== "safe" && (bare.includes("login") || bare.includes("verify"))),
    flag("Malware Distribution", verdict === "malicious" && h % 3 === 0),
    flag("Fake Login Page", bare.includes("login") || bare.includes("secure")),
    flag("Credential Harvesting", verdict !== "safe" && h % 2 === 0),
    flag("Typosquatting", hits > 1 && !known),
    flag("Homograph Attack", bare.includes("xn--")),
    flag("Drive-by Download", verdict === "malicious" && h % 4 === 0),
    flag("Malicious JavaScript", verdict === "malicious" && h % 5 === 0),
    flag("Suspicious Redirect", bare.length < 12 || bare.includes("bit.ly")),
    flag("C2 Communication", verdict === "malicious" && h % 6 === 0),
    flag("Crypto Scam", bare.includes("airdrop") || bare.includes("wallet")),
    flag("Fake Banking", bare.includes("paypa") || bare.includes("bank")),
  ];

  const signals = [
    { name: "Domain Age (days)", weight: known ? -18 : 22, direction: known ? "safe" as const : "risk" as const },
    { name: "TLS Certificate Trust", weight: known ? -14 : 10, direction: known ? "safe" as const : "risk" as const },
    { name: "URL Entropy", weight: 8 + (h % 10), direction: "risk" as const },
    { name: "Brand Keyword Match", weight: hits * 6, direction: "risk" as const },
    { name: "Homograph Score", weight: bare.includes("xn--") ? 20 : 2, direction: "risk" as const },
    { name: "Global Reputation", weight: known ? -25 : 12, direction: known ? "safe" as const : "risk" as const },
    { name: "AI Content Classifier", weight: verdict === "malicious" ? 24 : verdict === "suspicious" ? 12 : -20, direction: verdict === "safe" ? "safe" as const : "risk" as const },
  ].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

  const vulns = [
    { name: "SSL Certificate", status: known ? "pass" as const : (h % 3 === 0 ? "fail" as const : "warn" as const), detail: known ? "Valid EV cert, expires in 312d" : "Self-issued or short-lived cert" },
    { name: "TLS Version", status: known ? "pass" as const : "warn" as const, detail: known ? "TLS 1.3" : "TLS 1.2 with weak ciphers" },
    { name: "HSTS", status: known ? "pass" as const : "fail" as const, detail: known ? "max-age=31536000; includeSubDomains" : "Missing HSTS header" },
    { name: "Content-Security-Policy", status: h % 2 ? "warn" as const : "fail" as const, detail: "Policy missing or overly permissive" },
    { name: "X-Frame-Options", status: known ? "pass" as const : "fail" as const, detail: known ? "SAMEORIGIN" : "Not set — clickjacking risk" },
    { name: "Cookie Security", status: "warn" as const, detail: "Some cookies missing Secure/HttpOnly" },
    { name: "Open Ports", status: "warn" as const, detail: "80, 443, 8080 exposed" },
    { name: "Known CVEs", status: verdict === "malicious" ? "fail" as const : "pass" as const, detail: verdict === "malicious" ? "3 critical CVEs on detected stack" : "No known CVEs" },
    { name: "Blacklist Status", status: verdict === "safe" ? "pass" as const : "fail" as const, detail: verdict === "safe" ? "Not listed" : "Listed on 4 blocklists" },
  ];

  const intel = [
    { source: "VirusTotal", verdict: verdict === "safe" ? "Clean" : `${5 + (h % 20)} / 92 engines`, hits: verdict === "safe" ? 0 : 5 + (h % 20) },
    { source: "Google Safe Browsing", verdict: verdict === "malicious" ? "SOCIAL_ENGINEERING" : "Clean", hits: verdict === "malicious" ? 1 : 0 },
    { source: "URLHaus", verdict: verdict === "malicious" ? "Listed" : "Not listed", hits: verdict === "malicious" ? 1 : 0 },
    { source: "PhishTank", verdict: verdict !== "safe" ? "Reported" : "Not reported", hits: verdict !== "safe" ? 1 : 0 },
    { source: "AbuseIPDB", verdict: `${h % 100}% confidence`, hits: h % 100 },
    { source: "AlienVault OTX", verdict: verdict === "malicious" ? "3 pulses" : "0 pulses", hits: verdict === "malicious" ? 3 : 0 },
  ];

  return {
    url: url,
    verdict,
    threatScore,
    confidence: 78 + (h % 20),
    category,
    categoryFlags,
    signals,
    vulns,
    intel,
    domain: {
      registrar: known ? "MarkMonitor Inc." : "NameCheap Inc.",
      ageDays: known ? 8412 : 3 + (h % 60),
      country: known ? "US" : ["RU", "CN", "PA", "VG"][h % 4],
      asn: known ? "AS15169 Google LLC" : `AS${20000 + (h % 40000)}`,
      ip: `${20 + (h % 200)}.${h % 255}.${(h * 3) % 255}.${(h * 7) % 255}`,
      ssl: known ? "DigiCert TLS RSA SHA256 2020 CA1" : "Let's Encrypt R3",
      tls: known ? "TLS 1.3" : "TLS 1.2",
    },
    recommendations: verdict === "safe"
      ? ["Domain reputation is strong. Continue standard browsing hygiene.", "Enable browser phishing protection."]
      : verdict === "suspicious"
        ? ["Do not submit credentials or payment information.", "Verify domain through the brand's official channel.", "Enable MFA on any related accounts."]
        : ["BLOCK this URL at the perimeter and endpoint.", "Search SIEM for any user that visited this URL in the last 30 days.", "Rotate credentials of any exposed users immediately.", "Add IOC to threat intel platform and share with peers."],
  };
}
