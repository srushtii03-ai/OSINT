/**
 * Email scanner.
 * You can paste either a full raw email (headers + body) or just an address.
 * We check the three email-security records (SPF, DKIM, DMARC), look for
 * spoofing, pull every link out of the message, and run OSINT checks on them.
 */
import { doh, safeBrowsing, urlhaus, virusTotal, abuseIpdb, type Signal, type Vuln, type IntelSource } from "./scan-engine.server";
import { explainScan } from "./ai-explain.server";

export type UrlFinding = {
  url: string;
  host: string;
  ip: string | null;
  verdict: "safe" | "suspicious" | "malicious";
  sources: { source: string; verdict: string; hits: number }[];
};

export type EmailReport = {
  target: string;
  scanType: "email";
  host: string;
  verdict: "safe" | "suspicious" | "malicious";
  threatScore: number;
  securityScore: number;
  attackProbability: number;
  confidence: number;
  category: string;
  from: string | null;
  returnPath: string | null;
  replyTo: string | null;
  subject: string | null;
  auth: { spf: string; dkim: string; dmarc: string; alignment: string };
  records: { spf: string | null; dmarc: string | null; mx: string[] };
  hops: string[];
  urls: UrlFinding[];
  signals: Signal[];
  vulns: Vuln[];
  intel: IntelSource[];
  recommendations: string[];
  explanation?: string;
  durationMs: number;
  probeErrors: string[];
};

/** Split a raw email into its headers and its body. */
function splitEmail(raw: string) {
  const normalized = raw.replace(/\r\n/g, "\n");
  const idx = normalized.indexOf("\n\n");
  const headerBlock = idx === -1 ? normalized : normalized.slice(0, idx);
  const body = idx === -1 ? "" : normalized.slice(idx + 2);

  // Headers can wrap onto the next line if it starts with a space — join them back.
  const unfolded = headerBlock.replace(/\n[ \t]+/g, " ");
  const headers: Record<string, string[]> = {};
  for (const line of unfolded.split("\n")) {
    const m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
    if (!m) continue;
    const k = m[1].toLowerCase();
    (headers[k] ||= []).push(m[2].trim());
  }
  return { headers, body };
}

function firstHeader(h: Record<string, string[]>, name: string) {
  return h[name]?.[0] ?? null;
}

function addressDomain(value: string | null) {
  if (!value) return null;
  const m = value.match(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/);
  return m ? m[1].toLowerCase() : null;
}

/** Read the mail server's own verdict line, e.g. "spf=pass dkim=fail". */
function readAuthResults(lines: string[], what: "spf" | "dkim" | "dmarc") {
  for (const line of lines) {
    const m = line.toLowerCase().match(new RegExp(`${what}=(\\w+)`));
    if (m) return m[1];
  }
  return null;
}

function extractUrls(text: string) {
  const found = new Set<string>();
  const re = /https?:\/\/[^\s"'<>)\]]+/gi;
  for (const raw of text.match(re) ?? []) {
    const clean = raw.replace(/[.,;:]+$/, "");
    try {
      found.add(new URL(clean).toString());
    } catch {
      /* ignore malformed links */
    }
  }
  return [...found].slice(0, 8);
}

async function checkUrl(url: string, errors: string[]): Promise<UrlFinding> {
  const host = (() => { try { return new URL(url).hostname; } catch { return url; } })();
  const a = await doh(host, "A", errors);
  const ip = a.records.find((r) => /^\d{1,3}(\.\d{1,3}){3}$/.test(r)) ?? null;

  const [gsb, uh, vt, abuse] = await Promise.all([
    safeBrowsing(url, errors),
    urlhaus(url, errors),
    virusTotal(url, errors),
    ip ? abuseIpdb(ip, errors) : Promise.resolve(null),
  ]);

  const sources = [
    { source: "Google Safe Browsing", hits: gsb?.hits ?? 0, verdict: !gsb ? "not configured" : gsb.hits ? gsb.types.join(", ") : "clean" },
    { source: "URLHaus", hits: uh?.listed ? 1 : 0, verdict: !uh ? "unavailable" : uh.listed ? `listed — ${uh.threat}` : "not listed" },
    { source: "VirusTotal", hits: vt ? vt.malicious + vt.suspicious : 0, verdict: !vt ? "unavailable" : vt.known ? `${vt.malicious + vt.suspicious}/${vt.total} engines` : "not submitted" },
    { source: "AbuseIPDB", hits: abuse ? Math.round(abuse.score / 25) : 0, verdict: !abuse ? "not configured" : `${abuse.score}% abuse confidence` },
  ];

  const hits = sources.reduce((acc, s) => acc + s.hits, 0);
  return { url, host, ip, sources, verdict: hits >= 2 ? "malicious" : hits === 1 ? "suspicious" : "safe" };
}

export async function scanEmail(input: string): Promise<EmailReport> {
  const started = Date.now();
  const errors: string[] = [];
  const raw = input.trim();
  const looksRaw = /^[A-Za-z0-9-]+:\s/m.test(raw);

  const { headers, body } = looksRaw ? splitEmail(raw) : { headers: {} as Record<string, string[]>, body: raw };
  const from = looksRaw ? firstHeader(headers, "from") : raw;
  const returnPath = firstHeader(headers, "return-path");
  const replyTo = firstHeader(headers, "reply-to");
  const subject = firstHeader(headers, "subject");
  const authLines = [...(headers["authentication-results"] ?? []), ...(headers["received-spf"] ?? [])];

  const fromDomain = addressDomain(from) ?? raw.replace(/^.*@/, "").toLowerCase();
  const returnDomain = addressDomain(returnPath);
  const replyDomain = addressDomain(replyTo);

  // Live DNS lookups for the sending domain.
  const [spfTxt, dmarcTxt, mx] = await Promise.all([
    doh(fromDomain, "TXT", errors),
    doh(`_dmarc.${fromDomain}`, "TXT", errors),
    doh(fromDomain, "MX", errors),
  ]);
  const spfRecord = spfTxt.records.find((t) => t.startsWith("v=spf1")) ?? null;
  const dmarcRecord = dmarcTxt.records.find((t) => t.startsWith("v=DMARC1")) ?? null;

  const spfResult = readAuthResults(authLines, "spf") ?? (spfRecord ? "record published (not verified in transit)" : "no SPF record");
  const dkimResult =
    readAuthResults(authLines, "dkim") ?? (headers["dkim-signature"]?.length ? "signature present (not verified)" : "no DKIM signature");
  const dmarcResult = readAuthResults(authLines, "dmarc") ?? (dmarcRecord ? "policy published (not verified in transit)" : "no DMARC policy");

  const aligned = !returnDomain || returnDomain === fromDomain;
  const alignment = !returnDomain
    ? "No Return-Path header to compare"
    : aligned
      ? `Return-Path matches From (${fromDomain})`
      : `Return-Path ${returnDomain} does not match From ${fromDomain}`;

  const hops = (headers["received"] ?? []).slice(0, 6).map((h) => h.slice(0, 160));

  // Every link inside the email gets its own OSINT check.
  const urls = [];
  for (const url of extractUrls(body)) urls.push(await checkUrl(url, errors));

  const badUrls = urls.filter((u) => u.verdict !== "safe");
  const failed = (v: string) => /fail|none|no /i.test(v);

  const signals: Signal[] = [];
  const add = (name: string, weight: number, detail: string) =>
    signals.push({ name, weight: Math.round(weight), direction: weight >= 0 ? "risk" : "safe", detail });

  add("SPF Result", failed(spfResult) ? 22 : /pass/i.test(spfResult) ? -14 : 4, spfResult);
  add("DKIM Result", failed(dkimResult) ? 20 : /pass/i.test(dkimResult) ? -14 : 4, dkimResult);
  add("DMARC Policy", failed(dmarcResult) ? 18 : /pass|reject/i.test(dmarcResult) ? -12 : 4, dmarcResult);
  add("Envelope Alignment", aligned ? -8 : 26, alignment);
  add("Reply-To Mismatch", replyDomain && replyDomain !== fromDomain ? 20 : -4, replyDomain ? `Reply-To ${replyDomain}` : "No Reply-To header");
  add("Malicious Links", badUrls.length ? Math.min(45, badUrls.length * 22) : urls.length ? -8 : 0,
    badUrls.length ? badUrls.map((u) => u.host).join(", ") : `${urls.length} link(s), none flagged`);
  add("Urgency Wording", /urgent|verify your account|suspend|password expires|act now|final notice/i.test(body) ? 14 : -4,
    /urgent|verify|suspend/i.test(body) ? "Pressure wording found in body" : "No pressure wording");
  add("Attachment Lures", /\.(exe|scr|js|vbs|iso|hta|zip)\b/i.test(body) ? 15 : 0, "Risky attachment names referenced in body");
  add("Mail Infrastructure", mx.records.length ? -6 : 8, mx.records.length ? `${mx.records.length} MX record(s)` : "Domain has no MX records");

  signals.sort((x, y) => Math.abs(y.weight) - Math.abs(x.weight));

  const vulns: Vuln[] = [
    { name: "SPF", status: failed(spfResult) ? "fail" : /pass/i.test(spfResult) ? "pass" : "warn", severity: "medium", detail: spfRecord ?? spfResult, remediation: "Publish an SPF TXT record ending in -all." },
    { name: "DKIM", status: failed(dkimResult) ? "fail" : /pass/i.test(dkimResult) ? "pass" : "warn", severity: "medium", detail: dkimResult, remediation: "Sign all outbound mail with DKIM and publish the public key." },
    { name: "DMARC", status: failed(dmarcResult) ? "fail" : "pass", severity: "high", detail: dmarcRecord ?? dmarcResult, remediation: "Publish _dmarc TXT with p=reject and an rua address." },
    { name: "Envelope Alignment", status: aligned ? "pass" : "fail", severity: "high", detail: alignment, mitre: "T1566.002 Spearphishing Link", remediation: "Reject mail whose Return-Path domain differs from the From domain." },
    { name: "Embedded Links", status: badUrls.length ? "fail" : "pass", severity: "critical", detail: badUrls.length ? `${badUrls.length} flagged link(s)` : `${urls.length} link(s) checked, all clean`, remediation: "Block flagged links at the mail gateway and proxy." },
  ];

  const intel: IntelSource[] = [
    { source: "Google Safe Browsing", enabled: urls.some((u) => u.sources[0].verdict !== "not configured"), hits: urls.reduce((a, u) => a + u.sources[0].hits, 0), verdict: `${urls.length} link(s) checked` },
    { source: "URLHaus (abuse.ch)", enabled: urls.length > 0, hits: urls.reduce((a, u) => a + u.sources[1].hits, 0), verdict: `${urls.length} link(s) checked` },
    { source: "VirusTotal", enabled: urls.some((u) => u.sources[2].verdict !== "unavailable"), hits: urls.reduce((a, u) => a + u.sources[2].hits, 0), verdict: `${urls.length} link(s) checked` },
    { source: "AbuseIPDB", enabled: urls.some((u) => u.sources[3].verdict !== "not configured"), hits: urls.reduce((a, u) => a + u.sources[3].hits, 0), verdict: "sending infrastructure reputation" },
    { source: "Cloudflare DNS", enabled: true, hits: 0, verdict: `SPF ${spfRecord ? "found" : "missing"} · DMARC ${dmarcRecord ? "found" : "missing"}` },
  ];

  const rawRisk = signals.reduce((acc, s) => acc + s.weight, 0);
  const threatScore = Math.max(1, Math.min(99, Math.round(38 + rawRisk * 0.85)));
  const failWeight = vulns.reduce((acc, v) => acc + (v.status === "fail" ? 20 : v.status === "warn" ? 6 : 0), 0);
  const securityScore = Math.max(1, Math.min(100, 100 - failWeight));
  const attackProbability = Math.max(1, Math.min(99, Math.round(threatScore * 0.7 + (100 - securityScore) * 0.3)));
  const verdict: EmailReport["verdict"] = threatScore >= 72 ? "malicious" : threatScore >= 42 ? "suspicious" : "safe";
  const confidence = Math.max(45, Math.min(97, 55 + (looksRaw ? 15 : 0) + urls.length * 3 - errors.length * 3));

  const category = badUrls.length ? "Phishing Email (malicious link)"
    : !aligned ? "Spoofed Sender"
    : failed(dmarcResult) ? "Spoofable Domain"
    : verdict === "safe" ? "Legitimate" : "Suspicious Email";

  const base = { target: raw.slice(0, 120), scanType: "email" as const, host: fromDomain, verdict, threatScore, securityScore, attackProbability, confidence, category,
    from, returnPath, replyTo, subject, auth: { spf: spfResult, dkim: dkimResult, dmarc: dmarcResult, alignment },
    records: { spf: spfRecord, dmarc: dmarcRecord, mx: mx.records.slice(0, 4) }, hops, urls, signals, vulns, intel };

  const ai = await explainScan("email", { ...base, body: body.slice(0, 1500) }, errors);

  return {
    ...base,
    recommendations: ai?.recommendations?.length
      ? ai.recommendations
      : [
          badUrls.length ? "Block the flagged links at the mail gateway and web proxy." : "No malicious links found — keep monitoring.",
          "Warn the recipient not to click links or open attachments from this sender.",
          failed(dmarcResult) ? "Publish a DMARC policy (p=reject) for this domain." : "Keep the DMARC policy at p=reject.",
          "Search the mail logs for other copies of this message.",
        ],
    explanation: ai?.explanation ?? undefined,
    durationMs: Date.now() - started,
    probeErrors: errors,
  };
}
