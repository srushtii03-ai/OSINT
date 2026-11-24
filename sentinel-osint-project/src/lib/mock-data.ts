export const threatStats = {
  critical: 47,
  high: 213,
  medium: 892,
  low: 3204,
  totalScans: 128432,
  blockedToday: 1284,
  activeIncidents: 12,
  monitoredAssets: 4820,
};

export const threatFeed = [
  { id: "t1", time: "12s ago", severity: "critical", type: "Ransomware C2", source: "URLHaus", target: "185.220.101.42", country: "RU" },
  { id: "t2", time: "48s ago", severity: "high", type: "Phishing Kit", source: "OpenPhish", target: "paypa1-secure-login.com", country: "CN" },
  { id: "t3", time: "1m ago", severity: "high", type: "Credential Stealer", source: "AlienVault OTX", target: "vault-recover.io", country: "IR" },
  { id: "t4", time: "2m ago", severity: "medium", type: "Suspicious Redirect", source: "AI Engine", target: "bit.ly/xR2p9", country: "US" },
  { id: "t5", time: "3m ago", severity: "critical", type: "Malware Dropper", source: "VirusTotal", target: "94.156.68.211", country: "BG" },
  { id: "t6", time: "5m ago", severity: "low", type: "Scanner Activity", source: "GreyNoise", target: "45.132.9.8", country: "NL" },
  { id: "t7", time: "7m ago", severity: "high", type: "Crypto Scam", source: "PhishTank", target: "eth-airdrop-claim.xyz", country: "SG" },
  { id: "t8", time: "9m ago", severity: "medium", type: "Typosquat", source: "AI Engine", target: "githuub.io", country: "US" },
];

export const attackTrends = Array.from({ length: 24 }, (_, i) => ({
  hour: `${i}:00`,
  phishing: Math.round(80 + Math.sin(i / 3) * 40 + Math.random() * 30),
  malware: Math.round(60 + Math.cos(i / 4) * 30 + Math.random() * 25),
  ddos: Math.round(30 + Math.sin(i / 2) * 20 + Math.random() * 15),
  ransomware: Math.round(10 + Math.random() * 15),
}));

export const riskDistribution = [
  { name: "Critical", value: 47, color: "var(--critical)" },
  { name: "High", value: 213, color: "var(--high)" },
  { name: "Medium", value: 892, color: "var(--medium)" },
  { name: "Low", value: 3204, color: "var(--low)" },
];

export const topMalware = [
  { name: "Emotet", count: 1284, trend: "+12%" },
  { name: "LockBit 3.0", count: 982, trend: "+34%" },
  { name: "Qakbot", count: 764, trend: "-8%" },
  { name: "AgentTesla", count: 621, trend: "+4%" },
  { name: "RedLine Stealer", count: 512, trend: "+18%" },
  { name: "Cobalt Strike", count: 402, trend: "+2%" },
];

export const topActors = [
  { name: "APT29 (Cozy Bear)", origin: "RU", campaigns: 42 },
  { name: "Lazarus Group", origin: "KP", campaigns: 38 },
  { name: "APT41", origin: "CN", campaigns: 31 },
  { name: "FIN7", origin: "—", campaigns: 24 },
  { name: "Scattered Spider", origin: "US/UK", campaigns: 19 },
];

export const cves = [
  { id: "CVE-2026-2841", severity: "critical", cvss: 9.8, product: "Apache OFBiz", desc: "Remote code execution via crafted XML-RPC payload allowing unauthenticated attackers to gain shell access.", published: "2026-07-22", exploit: true },
  { id: "CVE-2026-2790", severity: "critical", cvss: 9.6, product: "Fortinet FortiOS", desc: "Authentication bypass in SSL VPN portal permits full admin takeover.", published: "2026-07-21", exploit: true },
  { id: "CVE-2026-2712", severity: "high", cvss: 8.4, product: "Microsoft Exchange", desc: "Privilege escalation via ProxyLogon-style deserialization flaw.", published: "2026-07-20", exploit: false },
  { id: "CVE-2026-2688", severity: "high", cvss: 8.1, product: "Cisco ASA", desc: "Memory corruption in IKEv2 handler leads to denial of service or RCE.", published: "2026-07-19", exploit: true },
  { id: "CVE-2026-2601", severity: "medium", cvss: 6.5, product: "WordPress Elementor", desc: "Stored XSS via unsanitized shortcode attribute processing.", published: "2026-07-18", exploit: false },
  { id: "CVE-2026-2544", severity: "medium", cvss: 6.1, product: "Node.js 22.x", desc: "HTTP request smuggling via malformed chunked encoding boundary.", published: "2026-07-17", exploit: false },
  { id: "CVE-2026-2489", severity: "critical", cvss: 9.9, product: "VMware vCenter", desc: "Unauthenticated RCE via SOAP endpoint deserialization.", published: "2026-07-16", exploit: true },
  { id: "CVE-2026-2401", severity: "low", cvss: 3.7, product: "OpenSSL 3.5", desc: "Timing side-channel in ECDSA signature generation.", published: "2026-07-15", exploit: false },
];

export const attackOrigins = [
  { country: "Russia", code: "RU", lat: 61, lng: 105, attacks: 4821, x: 62, y: 22 },
  { country: "China", code: "CN", lat: 35, lng: 104, attacks: 4103, x: 76, y: 38 },
  { country: "North Korea", code: "KP", lat: 40, lng: 127, attacks: 1892, x: 79, y: 35 },
  { country: "Iran", code: "IR", lat: 32, lng: 53, attacks: 1621, x: 58, y: 40 },
  { country: "USA", code: "US", lat: 39, lng: -98, attacks: 3241, x: 22, y: 40 },
  { country: "Brazil", code: "BR", lat: -14, lng: -51, attacks: 1104, x: 33, y: 68 },
  { country: "India", code: "IN", lat: 22, lng: 79, attacks: 1892, x: 68, y: 47 },
  { country: "Netherlands", code: "NL", lat: 52, lng: 5, attacks: 802, x: 49, y: 26 },
  { country: "Ukraine", code: "UA", lat: 49, lng: 32, attacks: 923, x: 55, y: 28 },
  { country: "Nigeria", code: "NG", lat: 9, lng: 8, attacks: 611, x: 50, y: 55 },
];

export const attackTargets = [
  { x: 22, y: 40 }, // US
  { x: 48, y: 30 }, // EU
  { x: 68, y: 47 }, // IN
  { x: 82, y: 60 }, // AU
  { x: 33, y: 68 }, // BR
];
