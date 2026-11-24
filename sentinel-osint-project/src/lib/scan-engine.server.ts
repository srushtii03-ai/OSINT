/**
 * Real scan engine. Runs entirely server-side (Cloudflare Worker compatible:
 * fetch + Web APIs only). Every probe is best-effort and degrades gracefully.
 */

export type Signal = { name: string; weight: number; direction: "risk" | "safe"; detail?: string };
export type Vuln = {
  name: string;
  status: "pass" | "warn" | "fail";
  severity: "critical" | "high" | "medium" | "low" | "safe";
  detail: string;
  owasp?: string;
  mitre?: string;
  remediation?: string;
};
export type IntelSource = { source: string; verdict: string; hits: number; enabled: boolean };

export type ScanReport = {
  target: string;
  scanType: "url" | "domain" | "ip" | "file" | "email";
  host: string;
  finalUrl?: string;
  verdict: "safe" | "suspicious" | "malicious";
  threatScore: number;
  securityScore: number;
  attackProbability: number;
  confidence: number;
  category: string;
  probabilities: { name: string; value: number }[];
  categoryFlags: { label: string; hit: boolean }[];
  signals: Signal[];
  vulns: Vuln[];
  intel: IntelSource[];
  domain: Record<string, string>;
  headers: Record<string, string>;
  technologies: string[];
  dns: { a: string[]; mx: string[]; ns: string[]; txt: string[]; dnssec: boolean };
  email: { spf: string | null; dmarc: string | null };
  recommendations: string[];
  explanation?: string;
  durationMs: number;
  probeErrors: string[];
};

const SUSPICIOUS_TOKENS = [
  "login", "verify", "secure", "account", "update", "wallet", "airdrop", "claim",
  "reset", "gift", "bonus", "confirm", "signin", "billing", "invoice", "support",
];
const BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "binance", "metamask", "facebook", "coinbase"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"];

export function timeout<T>(p: Promise<T>, ms: number, label: string, errors: string[]): Promise<T | null> {
  let settled = false;
  return Promise.race([
    p.then(
      (v) => { settled = true; return v; },
      (e) => { settled = true; errors.push(`${label}: ${String(e).slice(0, 120)}`); return null; },
    ),
    new Promise<null>((r) => setTimeout(() => { if (!settled) errors.push(`${label}: timeout`); r(null); }, ms)),
  ]);
}

function entropy(s: string) {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((acc, n) => {
    const p = n / s.length;
    return acc + p * Math.log2(p);
  }, 0);
}

function levenshtein(a: string, b: string) {
  const m = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) m[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      m[i][j] = Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return m[a.length][b.length];
}

export async function doh(name: string, type: string, errors: string[]) {
  const res = await timeout(
    fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
    }).then((r) => r.json() as Promise<{ Answer?: { data: string }[]; AD?: boolean }>),
    6000, `dns:${type}`, errors,
  );
  return { records: (res?.Answer ?? []).map((a) => a.data.replace(/^"|"$/g, "")), ad: Boolean(res?.AD) };
}

async function rdap(host: string, errors: string[]) {
  const res = await timeout(
    fetch(`https://rdap.org/domain/${encodeURIComponent(host)}`).then((r) => (r.ok ? r.json() : null)),
    7000, "rdap", errors,
  );
  if (!res) return null;
  const events: { eventAction: string; eventDate: string }[] = (res as any).events ?? [];
  const reg = events.find((e) => e.eventAction === "registration")?.eventDate;
  const exp = events.find((e) => e.eventAction === "expiration")?.eventDate;
  const registrar = ((res as any).entities ?? [])
    .flatMap((e: any) => (e.roles?.includes("registrar") ? [e.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3]] : []))
    .filter(Boolean)[0];
  return {
    registrar: registrar ?? "Unknown",
    registered: reg ?? null,
    expires: exp ?? null,
    ageDays: reg ? Math.round((Date.now() - new Date(reg).getTime()) / 86400000) : null,
    status: ((res as any).status ?? []).join(", "),
  };
}

async function ipInfo(ip: string, errors: string[]) {
  const res = await timeout(
    fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`).then((r) => (r.ok ? r.json() : null)),
    6000, "geoip", errors,
  );
  return res as { country_name?: string; org?: string; asn?: string; city?: string } | null;
}

/**
 * Checks that the VirusTotal key looks like a real key before we call the API.
 * A real VirusTotal key is 64 characters long and only uses 0-9 and a-f.
 */
export function validateVirusTotalKey(raw = process.env.VIRUSTOTAL_API_KEY) {
  const key = raw?.trim() ?? "";
  if (!key) return { ok: false as const, key: "", reason: "API key not configured" };
  if (!/^[a-fA-F0-9]{64}$/.test(key))
    return {
      ok: false as const,
      key: "",
      reason: `API key has a wrong format (${key.length} characters; a VirusTotal key is 64 hex characters)`,
    };
  return { ok: true as const, key, reason: "" };
}

/** Shared VirusTotal caller for both URL reports and file-hash reports. */
async function vtGet(path: string, label: string, errors: string[]) {
  const check = validateVirusTotalKey();
  if (!check.ok) {
    errors.push(`${label}: ${check.reason}`);
    return null;
  }
  return timeout(
    fetch(`https://www.virustotal.com/api/v3/${path}`, { headers: { "x-apikey": check.key } }).then(async (r) => {
      if (r.status === 404) return { notFound: true } as const;
      if (r.status === 401) throw new Error("401 Unauthorized — the VirusTotal key was rejected");
      if (r.status === 429) throw new Error("429 rate limited — free VirusTotal keys allow 4 requests/minute");
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    }),
    9000, label, errors,
  );
}

function vtStats(res: unknown) {
  const stats = (res as any)?.data?.attributes?.last_analysis_stats ?? {};
  const total = Object.values(stats).reduce((a: number, b: any) => a + Number(b || 0), 0) as number;
  return {
    known: true,
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    total,
  };
}

export async function virusTotal(url: string, errors: string[]) {
  const id = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const res = await vtGet(`urls/${id}`, "virustotal", errors);
  if (!res) return null;
  if ((res as any).notFound) return { known: false, malicious: 0, suspicious: 0, harmless: 0, total: 0 };
  return vtStats(res);
}

/** Look up a file by its SHA-256/SHA-1/MD5 hash in VirusTotal. */
export async function virusTotalFile(hash: string, errors: string[]) {
  const res = await vtGet(`files/${hash}`, "virustotal-file", errors);
  if (!res) return null;
  if ((res as any).notFound) return { known: false, malicious: 0, suspicious: 0, harmless: 0, total: 0, names: [] as string[], type: null as string | null };
  const attrs = (res as any).data?.attributes ?? {};
  return {
    ...vtStats(res),
    names: (attrs.names ?? []).slice(0, 5) as string[],
    type: (attrs.type_description ?? null) as string | null,
  };
}


export async function urlhaus(url: string, errors: string[]) {
  const res = await timeout(
    fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ url }),
    }).then((r) => r.json()),
    7000, "urlhaus", errors,
  );
  if (!res) return null;
  const q = (res as any).query_status;
  return { listed: q === "ok", threat: (res as any).threat ?? null, status: q };
}

/** AbuseIPDB keys are 80 lowercase hex characters. */
export function validateAbuseIpdbKey(raw = process.env.ABUSEIPDB_API_KEY) {
  const key = raw?.trim() ?? "";
  if (!key) return { ok: false as const, key: "", reason: "API key not configured" };
  if (!/^[a-fA-F0-9]{60,120}$/.test(key))
    return { ok: false as const, key: "", reason: `API key has a wrong format (${key.length} characters; an AbuseIPDB key is 80 hex characters)` };
  return { ok: true as const, key, reason: "" };
}

/** Google API keys start with "AIza" and are about 39 characters long. */
export function validateSafeBrowsingKey(raw = process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
  const key = raw?.trim() ?? "";
  if (!key) return { ok: false as const, key: "", reason: "API key not configured" };
  if (!/^AIza[0-9A-Za-z_-]{30,40}$/.test(key))
    return { ok: false as const, key: "", reason: `API key has a wrong format (${key.length} characters; a Google API key looks like "AIza…" and is ~39 characters)` };
  return { ok: true as const, key, reason: "" };
}

export async function abuseIpdb(ip: string, errors: string[]) {
  if (!ip) return null;
  const check = validateAbuseIpdbKey();
  if (!check.ok) {
    errors.push(`abuseipdb: ${check.reason}`);
    return null;
  }
  const res = await timeout(
    fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: check.key, Accept: "application/json" },
    }).then(async (r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status} — the AbuseIPDB key was rejected`);
      return r.json();
    }),
    7000, "abuseipdb", errors,
  );
  const d = (res as any)?.data;
  return d ? { score: Number(d.abuseConfidenceScore || 0), reports: Number(d.totalReports || 0) } : null;
}

export async function safeBrowsing(url: string, errors: string[]) {
  const check = validateSafeBrowsingKey();
  if (!check.ok) {
    errors.push(`safebrowsing: ${check.reason}`);
    return null;
  }
  const res = await timeout(
    fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${check.key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "sentinel-osint", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    }).then(async (r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status} — the Safe Browsing key was rejected`);
      return r.json();
    }),
    7000, "safebrowsing", errors,
  );
  if (!res) return null;
  const matches = (res as any)?.matches ?? [];
  return { hits: matches.length, types: matches.map((m: any) => m.threatType) };
}


function detectTech(html: string, headers: Record<string, string>) {
  const tech = new Set<string>();
  const server = headers["server"];
  if (server) tech.add(server);
  if (headers["x-powered-by"]) tech.add(headers["x-powered-by"]);
  const checks: [RegExp, string][] = [
    [/wp-content|wp-includes/i, "WordPress"],
    [/\/_next\//, "Next.js"],
    [/\/_nuxt\//, "Nuxt"],
    [/data-reactroot|react(-dom)?[.@]/i, "React"],
    [/ng-version=/i, "Angular"],
    [/cdn\.shopify\.com/i, "Shopify"],
    [/joomla/i, "Joomla"],
    [/drupal/i, "Drupal"],
    [/jquery[.-]/i, "jQuery"],
    [/bootstrap[.-]/i, "Bootstrap"],
    [/cloudflare/i, "Cloudflare"],
    [/googletagmanager|gtag\(/i, "Google Tag Manager"],
  ];
  for (const [re, name] of checks) if (re.test(html)) tech.add(name);
  return [...tech].slice(0, 14);
}

async function aiExplain(report: Omit<ScanReport, "recommendations" | "explanation">, errors: string[]) {
  const key = process.env.LOVABLE_API_KEY;
  if (!key) return null;
  const payload = {
    target: report.target,
    verdict: report.verdict,
    threatScore: report.threatScore,
    securityScore: report.securityScore,
    topSignals: report.signals.slice(0, 8),
    failedChecks: report.vulns.filter((v) => v.status !== "pass").map((v) => `${v.name}: ${v.detail}`),
    intel: report.intel.filter((i) => i.enabled),
    technologies: report.technologies,
  };
  const res = await timeout(
    fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json", "Lovable-API-Key": key, "X-Lovable-AIG-SDK": "fetch" },
      body: JSON.stringify({
        model: "google/gemini-3.5-flash",
        messages: [
          {
            role: "system",
            content:
              "You are a senior SOC analyst. Given scan telemetry, reply with strict JSON: " +
              '{"explanation": string (2-4 sentences, plain English, cites the strongest evidence), ' +
              '"recommendations": string[] (4-7 concrete, prioritised, actionable remediation steps)}. No markdown.',
          },
          { role: "user", content: JSON.stringify(payload) },
        ],
        response_format: { type: "json_object" },
      }),
    }).then(async (r) => {
      if (!r.ok) throw new Error(`gateway ${r.status}: ${(await r.text()).slice(0, 200)}`);
      return r.json();
    }),
    20000, "ai-explain", errors,
  );
  const content = (res as any)?.choices?.[0]?.message?.content;
  if (!content) return null;
  try {
    const parsed = JSON.parse(content);
    return {
      explanation: typeof parsed.explanation === "string" ? parsed.explanation : null,
      recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations.map(String).slice(0, 8) : [],
    };
  } catch {
    errors.push("ai-explain: unparsable response");
    return null;
  }
}

export function normalizeTarget(input: string, type: ScanReport["scanType"]) {
  const raw = input.trim();
  if (type === "email") return raw.toLowerCase();
  if (type === "ip") return raw;
  const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  return withProto;
}

export async function runScan(input: string, scanType: ScanReport["scanType"] = "url"): Promise<ScanReport> {
  const started = Date.now();
  const errors: string[] = [];
  const target = normalizeTarget(input, scanType);

  let host = target;
  let pathname = "/";
  let isHttps = false;
  if (scanType === "email") host = target.split("@")[1] ?? target;
  else if (scanType === "ip") host = target;
  else {
    try {
      const u = new URL(target);
      host = u.hostname;
      pathname = u.pathname + u.search;
      isHttps = u.protocol === "https:";
    } catch {
      errors.push("url: unparsable input");
    }
  }
  const bare = host.replace(/^www\./, "");

  // ---- Live HTTP probe -------------------------------------------------
  let headers: Record<string, string> = {};
  let statusCode: number | null = null;
  let finalUrl: string | undefined;
  let html = "";
  if (scanType === "url" || scanType === "domain") {
    const probe = await timeout(
      fetch(target, { redirect: "follow", headers: { "user-agent": "SentinelOSINT/1.0 (+security-scanner)" } }).then(
        async (r) => {
          const h: Record<string, string> = {};
          r.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
          const body = (await r.text()).slice(0, 200_000);
          return { h, status: r.status, url: r.url, body };
        },
      ),
      12000, "http", errors,
    );
    if (probe) {
      headers = probe.h;
      statusCode = probe.status;
      finalUrl = probe.url;
      html = probe.body;
      if (probe.url.startsWith("https://")) isHttps = true;
    }
  }

  // ---- DNS / WHOIS / geo ----------------------------------------------
  const isIpTarget = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const [a, mx, ns, txt, dmarcRec, whois] = await Promise.all([
    isIpTarget ? Promise.resolve({ records: [host], ad: false }) : doh(host, "A", errors),
    doh(bare, "MX", errors),
    doh(bare, "NS", errors),
    doh(bare, "TXT", errors),
    doh(`_dmarc.${bare}`, "TXT", errors),
    isIpTarget ? Promise.resolve(null) : rdap(bare, errors),
  ]);
  const ip = a.records.find((r) => /^\d{1,3}(\.\d{1,3}){3}$/.test(r)) ?? "";
  const geo = ip ? await ipInfo(ip, errors) : null;
  const spf = txt.records.find((t) => t.startsWith("v=spf1")) ?? null;
  const dmarc = dmarcRec.records.find((t) => t.startsWith("v=DMARC1")) ?? null;

  // ---- OSINT feeds -----------------------------------------------------
  const [vt, uh, abuse, gsb] = await Promise.all([
    scanType === "email" ? Promise.resolve(null) : virusTotal(target, errors),
    scanType === "email" ? Promise.resolve(null) : urlhaus(target, errors),
    abuseIpdb(ip, errors),
    scanType === "email" ? Promise.resolve(null) : safeBrowsing(target, errors),
  ]);

  const intel: IntelSource[] = [
    {
      source: "VirusTotal",
      enabled: vt !== null,
      hits: vt ? vt.malicious + vt.suspicious : 0,
      verdict: !vt
        ? validateVirusTotalKey().reason || errors.find((e) => e.startsWith("virustotal")) || "unavailable"
        : !vt.known ? "URL not yet submitted" : `${vt.malicious + vt.suspicious} / ${vt.total} engines flagged`,
    },
    {
      source: "Google Safe Browsing",
      enabled: gsb !== null,
      hits: gsb?.hits ?? 0,
      verdict: !gsb
        ? validateSafeBrowsingKey().reason || errors.find((e) => e.startsWith("safebrowsing")) || "unavailable"
        : gsb.hits ? gsb.types.join(", ") : "Clean",
    },
    {
      source: "URLHaus (abuse.ch)",
      enabled: uh !== null,
      hits: uh?.listed ? 1 : 0,
      verdict: !uh ? "Unavailable" : uh.listed ? `Listed — ${uh.threat}` : "Not listed",
    },
    {
      source: "AbuseIPDB",
      enabled: abuse !== null,
      hits: abuse ? Math.round(abuse.score / 25) : 0,
      verdict: !abuse
        ? validateAbuseIpdbKey().reason || errors.find((e) => e.startsWith("abuseipdb")) || "no IP to check"
        : `${abuse.score}% abuse confidence · ${abuse.reports} reports`,
    },
    {
      source: "Cloudflare DNS / RDAP",
      enabled: true,
      hits: 0,
      verdict: whois ? `Registered ${whois.registered?.slice(0, 10) ?? "unknown"}` : "No RDAP record",
    },
  ];

  // ---- Lexical / heuristic features -----------------------------------
  const lowerTarget = target.toLowerCase();
  const tokenHits = SUSPICIOUS_TOKENS.filter((t) => lowerTarget.includes(t));
  const brandHit = BRANDS.find((b) => bare.includes(b) && !bare.endsWith(`${b}.com`));
  const typosquat = BRANDS.some((b) => {
    const label = bare.split(".")[0];
    const d = levenshtein(label, b);
    return d > 0 && d <= 2;
  });
  const homograph = bare.includes("xn--");
  const shortener = SHORTENERS.some((s) => bare.endsWith(s));
  const ent = entropy(bare);
  const ageDays = whois?.ageDays ?? null;

  // ---- Security header / vuln audit -----------------------------------
  const hdr = (k: string) => headers[k];
  const vulns: Vuln[] = [];
  const push = (v: Vuln) => vulns.push(v);
  const probed = Object.keys(headers).length > 0;

  push({
    name: "HTTPS Enforced",
    status: isHttps ? "pass" : "fail",
    severity: isHttps ? "safe" : "high",
    detail: isHttps ? `Served over HTTPS (final URL ${finalUrl ?? target})` : "Site is not served over HTTPS — traffic can be intercepted.",
    owasp: "A02:2021 Cryptographic Failures",
    mitre: "T1040 Network Sniffing",
    remediation: "Terminate TLS at the edge and 301-redirect all HTTP traffic to HTTPS.",
  });
  push({
    name: "HSTS",
    status: hdr("strict-transport-security") ? "pass" : probed ? "fail" : "warn",
    severity: hdr("strict-transport-security") ? "safe" : "medium",
    detail: hdr("strict-transport-security") ?? (probed ? "Missing Strict-Transport-Security header" : "Not probed"),
    owasp: "A05:2021 Security Misconfiguration",
    remediation: "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
  });
  push({
    name: "Content-Security-Policy",
    status: hdr("content-security-policy") ? (/unsafe-inline|unsafe-eval|\*/.test(hdr("content-security-policy")!) ? "warn" : "pass") : probed ? "fail" : "warn",
    severity: hdr("content-security-policy") ? "low" : "high",
    detail: hdr("content-security-policy")?.slice(0, 180) ?? (probed ? "No CSP — XSS payloads execute unrestricted" : "Not probed"),
    owasp: "A03:2021 Injection",
    mitre: "T1189 Drive-by Compromise",
    remediation: "Ship a nonce-based CSP; remove 'unsafe-inline' and wildcard sources.",
  });
  push({
    name: "X-Frame-Options / frame-ancestors",
    status: hdr("x-frame-options") || /frame-ancestors/.test(hdr("content-security-policy") ?? "") ? "pass" : probed ? "fail" : "warn",
    severity: "medium",
    detail: hdr("x-frame-options") ?? (probed ? "Clickjacking possible — no framing restriction" : "Not probed"),
    owasp: "A05:2021 Security Misconfiguration",
    remediation: "Set `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
  });
  push({
    name: "X-Content-Type-Options",
    status: hdr("x-content-type-options") === "nosniff" ? "pass" : probed ? "fail" : "warn",
    severity: "low",
    detail: hdr("x-content-type-options") ?? (probed ? "MIME sniffing not disabled" : "Not probed"),
    remediation: "Set `X-Content-Type-Options: nosniff`.",
  });
  push({
    name: "Referrer-Policy",
    status: hdr("referrer-policy") ? "pass" : probed ? "warn" : "warn",
    severity: "low",
    detail: hdr("referrer-policy") ?? "No Referrer-Policy — full URLs leak to third parties",
    remediation: "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
  });
  push({
    name: "Permissions-Policy",
    status: hdr("permissions-policy") ? "pass" : "warn",
    severity: "low",
    detail: hdr("permissions-policy") ?? "No Permissions-Policy — powerful browser APIs unrestricted",
    remediation: "Deny unused features, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
  });
  const cookies = headers["set-cookie"] ?? "";
  push({
    name: "Cookie Security",
    status: !cookies ? "pass" : /HttpOnly/i.test(cookies) && /Secure/i.test(cookies) ? "pass" : "fail",
    severity: "medium",
    detail: !cookies ? "No cookies set on the landing response" : `Set-Cookie flags: ${/Secure/i.test(cookies) ? "Secure " : ""}${/HttpOnly/i.test(cookies) ? "HttpOnly " : ""}${/SameSite/i.test(cookies) ? "SameSite" : "(SameSite missing)"}`,
    owasp: "A07:2021 Identification and Authentication Failures",
    remediation: "Set Secure, HttpOnly and SameSite=Lax/Strict on every session cookie.",
  });
  push({
    name: "Server Banner Disclosure",
    status: hdr("server") || hdr("x-powered-by") ? "warn" : "pass",
    severity: "low",
    detail: [hdr("server"), hdr("x-powered-by")].filter(Boolean).join(" · ") || "No stack banners exposed",
    owasp: "A05:2021 Security Misconfiguration",
    remediation: "Strip `Server` and `X-Powered-By` headers at the reverse proxy.",
  });
  push({
    name: "Mixed Content",
    status: isHttps && /src=["']http:\/\//i.test(html) ? "fail" : "pass",
    severity: "medium",
    detail: isHttps && /src=["']http:\/\//i.test(html) ? "Insecure http:// subresources found in HTML" : "No insecure subresources detected",
    remediation: "Load all subresources over HTTPS or add `upgrade-insecure-requests`.",
  });
  push({
    name: "DNSSEC",
    status: a.ad ? "pass" : "warn",
    severity: "low",
    detail: a.ad ? "DNSSEC validated (AD flag set)" : "DNSSEC not validated — DNS spoofing risk",
    remediation: "Enable DNSSEC signing at your registrar and DNS provider.",
  });
  push({
    name: "SPF Record",
    status: spf ? "pass" : "fail",
    severity: "medium",
    detail: spf ?? "No SPF record — domain can be spoofed in email",
    remediation: "Publish an SPF TXT record ending in `-all`.",
  });
  push({
    name: "DMARC Record",
    status: dmarc ? (/p=reject|p=quarantine/.test(dmarc) ? "pass" : "warn") : "fail",
    severity: "medium",
    detail: dmarc ?? "No DMARC policy — spoofed mail is not rejected",
    remediation: "Publish `_dmarc` TXT with `v=DMARC1; p=reject; rua=mailto:...`.",
  });
  push({
    name: "Domain Age",
    status: ageDays === null ? "warn" : ageDays < 90 ? "fail" : ageDays < 365 ? "warn" : "pass",
    severity: ageDays !== null && ageDays < 90 ? "high" : "low",
    detail: ageDays === null ? "Registration date unavailable" : `Registered ${ageDays} days ago (${whois?.registrar ?? "unknown registrar"})`,
    remediation: "Newly registered domains are heavily abused — treat with elevated scrutiny.",
  });
  push({
    name: "Blacklist Status",
    status: (vt && vt.malicious > 0) || uh?.listed || (gsb?.hits ?? 0) > 0 ? "fail" : "pass",
    severity: "critical",
    detail:
      (vt && vt.malicious > 0) || uh?.listed || (gsb?.hits ?? 0) > 0
        ? `Flagged by ${[vt && vt.malicious > 0 && "VirusTotal", uh?.listed && "URLHaus", (gsb?.hits ?? 0) > 0 && "Safe Browsing"].filter(Boolean).join(", ")}`
        : "Not present on queried blocklists",
    mitre: "T1566 Phishing",
    remediation: "Block at perimeter and endpoint, then hunt for prior visits in SIEM.",
  });
  if (statusCode !== null) {
    push({
      name: "HTTP Response",
      status: statusCode < 400 ? "pass" : "warn",
      severity: "low",
      detail: `HTTP ${statusCode}${finalUrl && finalUrl !== target ? ` after redirect to ${finalUrl}` : ""}`,
      remediation: "N/A",
    });
  }

  // ---- Normalized scoring model ---------------------------------------
  const signals: Signal[] = [];
  const add = (name: string, weight: number, detail: string) =>
    signals.push({ name, weight: Math.round(weight), direction: weight >= 0 ? "risk" : "safe", detail });

  add("Blocklist Reputation",
    vt && vt.malicious > 0 ? Math.min(45, 12 + vt.malicious * 4) : uh?.listed ? 40 : (gsb?.hits ?? 0) > 0 ? 45 : vt?.known ? -18 : 0,
    intel.filter((i) => i.enabled && i.hits > 0).map((i) => i.source).join(", ") || "No blocklist hits");
  add("Domain Age", ageDays === null ? 4 : ageDays < 30 ? 26 : ageDays < 90 ? 18 : ageDays < 365 ? 8 : -16,
    ageDays === null ? "Unknown" : `${ageDays} days`);
  add("Transport Security", isHttps ? -12 : 22, isHttps ? "HTTPS in use" : "No HTTPS");
  add("Security Header Posture",
    (() => {
      const failed = vulns.filter((v) => ["HSTS", "Content-Security-Policy", "X-Frame-Options / frame-ancestors", "X-Content-Type-Options"].includes(v.name) && v.status === "fail").length;
      return failed * 5 - (failed === 0 ? 10 : 0);
    })(),
    `${vulns.filter((v) => v.status === "fail").length} failing checks`);
  add("Brand Impersonation", brandHit ? 24 : typosquat ? 20 : -6, brandHit ? `Brand token "${brandHit}" on non-official domain` : typosquat ? "Edit distance ≤2 from a major brand" : "No brand collision");
  add("Suspicious Keywords", tokenHits.length * 6, tokenHits.join(", ") || "None");
  add("URL Entropy", ent > 3.7 ? 12 : ent > 3.2 ? 6 : -4, `Shannon entropy ${ent.toFixed(2)}`);
  add("Homograph / Punycode", homograph ? 28 : -2, homograph ? "Punycode label detected" : "ASCII label");
  add("URL Shortener", shortener ? 16 : 0, shortener ? "Known shortener — destination hidden" : "Direct domain");
  add("IP Abuse History", abuse ? Math.round(abuse.score * 0.3) : 0, abuse ? `${abuse.score}% AbuseIPDB confidence` : "Not queried");
  add("Email Authentication", (spf ? -4 : 6) + (dmarc ? -4 : 6), `${spf ? "SPF" : "no SPF"} · ${dmarc ? "DMARC" : "no DMARC"}`);
  add("Path Complexity", pathname.length > 60 ? 8 : pathname.split("/").length > 5 ? 5 : -2, `Path length ${pathname.length}`);

  signals.sort((x, y) => Math.abs(y.weight) - Math.abs(x.weight));

  const rawRisk = signals.reduce((acc, s) => acc + s.weight, 0);
  const threatScore = Math.max(1, Math.min(99, Math.round(38 + rawRisk * 0.85)));
  const headerChecks = vulns.filter((v) => v.severity !== "safe");
  const failWeight = headerChecks.reduce((acc, v) => acc + (v.status === "fail" ? ({ critical: 25, high: 14, medium: 8, low: 4, safe: 0 } as const)[v.severity] : v.status === "warn" ? 3 : 0), 0);
  const securityScore = Math.max(1, Math.min(100, 100 - failWeight));
  const attackProbability = Math.max(1, Math.min(99, Math.round(threatScore * 0.7 + (100 - securityScore) * 0.3)));
  const verdict: ScanReport["verdict"] = threatScore >= 72 ? "malicious" : threatScore >= 42 ? "suspicious" : "safe";

  const probedSources = intel.filter((i) => i.enabled).length;
  const confidence = Math.max(45, Math.min(97, 50 + probedSources * 8 + (probed ? 10 : 0) + (whois ? 5 : 0) - errors.length * 3));

  const category =
    (gsb?.hits ?? 0) > 0 ? gsb!.types[0]?.replace(/_/g, " ") ?? "Malicious"
      : uh?.listed ? `Malware Distribution (${uh.threat})`
      : brandHit || typosquat ? "Typosquat / Brand Impersonation"
      : tokenHits.includes("login") || tokenHits.includes("verify") ? "Credential Harvesting Pattern"
      : verdict === "safe" ? "Legitimate" : "Suspicious Infrastructure";

  const p = (base: number, mult = 1) => Math.max(1, Math.min(99, Math.round(base * mult)));
  const probabilities = [
    { name: "Phishing", value: p(threatScore, brandHit || tokenHits.includes("login") ? 1.15 : 0.7) },
    { name: "Malware Delivery", value: p(threatScore, uh?.listed ? 1.2 : 0.6) },
    { name: "Credential Theft", value: p(threatScore, tokenHits.length ? 1.1 : 0.55) },
    { name: "Data Leak", value: p(100 - securityScore, 0.8) },
    { name: "Ransomware", value: p(threatScore, 0.45) },
    { name: "Social Engineering", value: p(threatScore, 0.9) },
    { name: "Browser Exploit", value: p(threatScore, 0.5) },
    { name: "Overall Attack", value: attackProbability },
  ];

  const categoryFlags = [
    { label: "Phishing Pattern", hit: Boolean(brandHit) || tokenHits.includes("login") || tokenHits.includes("verify") },
    { label: "Malware Distribution", hit: Boolean(uh?.listed) || (gsb?.types ?? []).includes("MALWARE") },
    { label: "Fake Login Page", hit: /type=["']password["']/i.test(html) && verdict !== "safe" },
    { label: "Credential Harvesting", hit: /type=["']password["']/i.test(html) && !isHttps },
    { label: "Typosquatting", hit: typosquat },
    { label: "Homograph Attack", hit: homograph },
    { label: "URL Shortener Abuse", hit: shortener },
    { label: "Suspicious Redirect", hit: Boolean(finalUrl && new URL(finalUrl).hostname !== host) },
    { label: "Newly Registered Domain", hit: ageDays !== null && ageDays < 90 },
    { label: "Crypto Scam Keywords", hit: /airdrop|wallet|seed phrase|metamask/i.test(lowerTarget + html.slice(0, 5000)) },
    { label: "Missing Transport Security", hit: !isHttps },
    { label: "Blocklisted", hit: Boolean((vt && vt.malicious > 0) || uh?.listed || (gsb?.hits ?? 0) > 0) },
  ];

  const base: Omit<ScanReport, "recommendations" | "explanation"> = {
    target,
    scanType,
    host,
    finalUrl,
    verdict,
    threatScore,
    securityScore,
    attackProbability,
    confidence,
    category,
    probabilities,
    categoryFlags,
    signals,
    vulns,
    intel,
    headers,
    technologies: detectTech(html, headers),
    dns: { a: a.records, mx: mx.records, ns: ns.records, txt: txt.records.slice(0, 6), dnssec: a.ad },
    email: { spf, dmarc },
    domain: {
      host,
      ip: ip || "unresolved",
      registrar: whois?.registrar ?? "unknown",
      registered: whois?.registered?.slice(0, 10) ?? "unknown",
      expires: whois?.expires?.slice(0, 10) ?? "unknown",
      ageDays: ageDays === null ? "unknown" : String(ageDays),
      country: geo?.country_name ?? "unknown",
      asn: geo?.asn ? `${geo.asn} ${geo.org ?? ""}`.trim() : geo?.org ?? "unknown",
      nameServers: ns.records.slice(0, 2).join(", ") || "unknown",
      httpStatus: statusCode === null ? "no response" : String(statusCode),
    },
    durationMs: Date.now() - started,
    probeErrors: errors,
  };

  const ai = await aiExplain(base, errors);
  const fallbackRecs =
    verdict === "safe"
      ? ["No blocklist hits — continue routine monitoring.", ...vulns.filter((v) => v.status !== "pass").slice(0, 4).map((v) => v.remediation ?? v.detail)]
      : ["Block this destination at the proxy and endpoint agents.", "Hunt SIEM/proxy logs for visits in the last 30 days.", "Rotate credentials for any user who submitted data.", ...vulns.filter((v) => v.status === "fail").slice(0, 3).map((v) => v.remediation ?? v.detail)];

  return {
    ...base,
    durationMs: Date.now() - started,
    explanation: ai?.explanation ?? undefined,
    recommendations: ai?.recommendations?.length ? ai.recommendations : fallbackRecs.filter(Boolean),
  };
}
