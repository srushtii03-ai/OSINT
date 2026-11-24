/**
 * File scanner.
 * We never execute the file. We only read its bytes, calculate its "hashes"
 * (a hash is a short fingerprint of the file), and ask OSINT services whether
 * that fingerprint is known malware.
 */
import { virusTotalFile, urlhaus, timeout, type Signal, type Vuln, type IntelSource } from "./scan-engine.server";
import { explainScan } from "./ai-explain.server";

export type FileReport = {
  target: string;
  scanType: "file";
  host: string;
  fileName: string;
  size: number;
  fileType: string;
  hashes: { sha256: string; sha1: string; md5: string };
  verdict: "safe" | "suspicious" | "malicious";
  threatScore: number;
  securityScore: number;
  attackProbability: number;
  confidence: number;
  category: string;
  entropy: number;
  strings: string[];
  signals: Signal[];
  vulns: Vuln[];
  intel: IntelSource[];
  recommendations: string[];
  explanation?: string;
  durationMs: number;
  probeErrors: string[];
};

const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

/** Tiny MD5 implementation — the Web Crypto API does not provide MD5. */
function md5(bytes: Uint8Array) {
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296));
  const len = bytes.length;
  const withPad = new Uint8Array((((len + 8) >> 6) + 1) * 64);
  withPad.set(bytes);
  withPad[len] = 0x80;
  const view = new DataView(withPad.buffer);
  view.setUint32(withPad.length - 8, (len << 3) >>> 0, true);
  view.setUint32(withPad.length - 4, Math.floor(len / 536870912), true);

  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  const rol = (x: number, c: number) => (x << c) | (x >>> (32 - c));

  for (let i = 0; i < withPad.length; i += 64) {
    const M = Array.from({ length: 16 }, (_, j) => view.getUint32(i + j * 4, true));
    let [A, B, C, D] = [a0, b0, c0, d0];
    for (let j = 0; j < 64; j++) {
      let F: number, g: number;
      if (j < 16) { F = (B & C) | (~B & D); g = j; }
      else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
      else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * j) % 16; }
      F = (F + A + K[j] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rol(F, S[j])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  return [a0, b0, c0, d0]
    .map((n) => [...new Uint8Array(new Uint32Array([n]).buffer)].map((b) => b.toString(16).padStart(2, "0")).join(""))
    .join("");
}

/** How random the bytes look. High randomness often means packed/encrypted malware. */
function byteEntropy(bytes: Uint8Array) {
  const freq = new Array(256).fill(0);
  for (const b of bytes) freq[b]++;
  let e = 0;
  for (const n of freq) if (n) { const p = n / bytes.length; e -= p * Math.log2(p); }
  return e;
}

/** Guess the file type from its first bytes ("magic bytes"). */
function magicType(bytes: Uint8Array, name: string) {
  const sig = [...bytes.slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (sig.startsWith("4d5a")) return "Windows executable (PE/EXE/DLL)";
  if (sig.startsWith("7f454c46")) return "Linux executable (ELF)";
  if (sig.startsWith("25504446")) return "PDF document";
  if (sig.startsWith("504b0304")) return name.toLowerCase().endsWith(".apk") ? "Android package (APK)" : "ZIP / Office document";
  if (sig.startsWith("d0cf11e0")) return "Legacy Office document (OLE)";
  if (sig.startsWith("cafebabe")) return "Java class file";
  return "Unknown / plain data";
}

/** Look up a malware sample by hash on abuse.ch MalwareBazaar. */
async function malwareBazaar(sha256: string, errors: string[]) {
  const res = await timeout(
    fetch("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ query: "get_info", hash: sha256 }),
    }).then((r) => (r.ok ? r.json() : null)),
    8000, "malwarebazaar", errors,
  );
  const status = (res as any)?.query_status;
  if (!res || (status && status !== "ok" && status !== "hash_not_found")) return null;
  const item = (res as any)?.data?.[0];
  return { listed: Boolean(item), family: item?.signature ?? null, fileType: item?.file_type ?? null, tags: item?.tags ?? [] };
}

const RISKY_EXT = ["exe", "dll", "scr", "js", "vbs", "hta", "ps1", "bat", "cmd", "jar", "iso", "lnk", "apk", "msi"];

export async function scanFile(bytes: Uint8Array, fileName: string): Promise<FileReport> {
  const started = Date.now();
  const errors: string[] = [];

  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const [sha256Buf, sha1Buf] = await Promise.all([
    crypto.subtle.digest("SHA-256", buffer),
    crypto.subtle.digest("SHA-1", buffer),
  ]);
  const hashes = { sha256: hex(sha256Buf), sha1: hex(sha1Buf), md5: md5(bytes) };

  const fileType = magicType(bytes, fileName);
  const ext = (fileName.split(".").pop() ?? "").toLowerCase();
  const doubleExt = /\.(pdf|doc|docx|xls|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd)$/i.test(fileName);
  const ent = byteEntropy(bytes.slice(0, 200_000));

  // Readable text inside the file often reveals what it tries to do.
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, 200_000));
  const iocs = [
    ["PowerShell execution", /powershell|Invoke-Expression|IEX\s*\(/i],
    ["Office macro", /AutoOpen|Auto_Open|Document_Open|vbaProject\.bin/i],
    ["Shell command", /cmd\.exe|WScript\.Shell|ShellExecute/i],
    ["Network download", /URLDownloadToFile|WebClient|DownloadString|curl\s+http/i],
    ["Registry persistence", /CurrentVersion\\\\Run|schtasks|reg add/i],
    ["Credential access", /mimikatz|LSASS|SAM\\\\Domains/i],
    ["Ransom note wording", /your files (have been|are) encrypted|bitcoin wallet/i],
  ] as const;
  const hitIocs = iocs.filter(([, re]) => re.test(text)).map(([label]) => label);
  const urlsInside = (text.match(/https?:\/\/[^\s"'<>)]+/g) ?? []).slice(0, 5);

  const [vt, mb, uh] = await Promise.all([
    virusTotalFile(hashes.sha256, errors),
    malwareBazaar(hashes.sha256, errors),
    urlsInside[0] ? urlhaus(urlsInside[0], errors) : Promise.resolve(null),
  ]);

  const intel: IntelSource[] = [
    {
      source: "VirusTotal (file hash)",
      enabled: vt !== null,
      hits: vt ? vt.malicious + vt.suspicious : 0,
      verdict: !vt ? errors.find((e) => e.startsWith("virustotal-file")) ?? "unavailable"
        : vt.known ? `${vt.malicious + vt.suspicious} / ${vt.total} engines flagged` : "hash not seen before",
    },
    {
      source: "MalwareBazaar (abuse.ch)",
      enabled: mb !== null,
      hits: mb?.listed ? 1 : 0,
      verdict: !mb ? "unavailable" : mb.listed ? `Known sample — ${mb.family ?? "unclassified"}` : "hash not listed",
    },
    {
      source: "URLHaus (embedded links)",
      enabled: uh !== null,
      hits: uh?.listed ? 1 : 0,
      verdict: !uh ? (urlsInside.length ? "unavailable" : "no links inside file") : uh.listed ? `Listed — ${uh.threat}` : "links not listed",
    },
  ];

  const signals: Signal[] = [];
  const add = (name: string, weight: number, detail: string) =>
    signals.push({ name, weight: Math.round(weight), direction: weight >= 0 ? "risk" : "safe", detail });

  add("Antivirus Detections", vt?.known ? (vt.malicious ? Math.min(50, 15 + vt.malicious * 3) : -20) : 0,
    vt?.known ? `${vt.malicious} malicious / ${vt.total} engines` : "hash unknown to VirusTotal");
  add("Known Malware Sample", mb?.listed ? 45 : mb ? -10 : 0, mb?.listed ? `MalwareBazaar family ${mb.family}` : "not in MalwareBazaar");
  add("Executable Content", /executable|APK|Java/i.test(fileType) ? 18 : -6, fileType);
  add("Risky Extension", RISKY_EXT.includes(ext) ? 14 : -4, ext ? `.${ext}` : "no extension");
  add("Double Extension", doubleExt ? 30 : -2, doubleExt ? "File hides its real type behind a fake one" : "single extension");
  add("Packing / Encryption", ent > 7.2 ? 16 : ent > 6.5 ? 8 : -6, `Byte entropy ${ent.toFixed(2)} / 8`);
  add("Suspicious Behaviour Strings", hitIocs.length * 9, hitIocs.join(", ") || "none found");
  add("Embedded Links", uh?.listed ? 30 : urlsInside.length ? 5 : 0, urlsInside.length ? `${urlsInside.length} link(s) inside file` : "no links");

  signals.sort((x, y) => Math.abs(y.weight) - Math.abs(x.weight));

  const vulns: Vuln[] = [
    { name: "Antivirus Reputation", status: vt?.malicious ? "fail" : vt?.known ? "pass" : "warn", severity: "critical",
      detail: intel[0].verdict, mitre: "T1204 User Execution", remediation: "Quarantine the file and block its hash on endpoints." },
    { name: "Malware Family Match", status: mb?.listed ? "fail" : "pass", severity: "critical",
      detail: intel[1].verdict, remediation: "Follow the incident playbook for the identified family." },
    { name: "File Type vs Extension", status: doubleExt ? "fail" : "pass", severity: "high",
      detail: doubleExt ? "Double extension detected" : `${fileType} matches .${ext || "none"}`, remediation: "Block double-extension attachments at the gateway." },
    { name: "Static Behaviour Indicators", status: hitIocs.length > 2 ? "fail" : hitIocs.length ? "warn" : "pass", severity: "high",
      detail: hitIocs.join(", ") || "No dangerous API or macro strings found", remediation: "Detonate the file in a sandbox before allowing it." },
    { name: "Entropy / Packing", status: ent > 7.2 ? "warn" : "pass", severity: "medium",
      detail: `Entropy ${ent.toFixed(2)}`, remediation: "Packed files should be unpacked and re-analysed." },
  ];

  const rawRisk = signals.reduce((acc, s) => acc + s.weight, 0);
  const threatScore = Math.max(1, Math.min(99, Math.round(35 + rawRisk * 0.85)));
  const failWeight = vulns.reduce((acc, v) => acc + (v.status === "fail" ? 22 : v.status === "warn" ? 7 : 0), 0);
  const securityScore = Math.max(1, Math.min(100, 100 - failWeight));
  const attackProbability = Math.max(1, Math.min(99, Math.round(threatScore * 0.75 + (100 - securityScore) * 0.25)));
  const verdict: FileReport["verdict"] = threatScore >= 72 ? "malicious" : threatScore >= 42 ? "suspicious" : "safe";
  const confidence = Math.max(45, Math.min(97, 50 + intel.filter((i) => i.enabled).length * 12 - errors.length * 3));

  const category = mb?.listed ? `Known Malware (${mb.family ?? "unclassified"})`
    : vt?.malicious ? "Malicious File"
    : hitIocs.includes("Ransom note wording") ? "Ransomware Indicator"
    : hitIocs.includes("Office macro") ? "Macro Document"
    : verdict === "safe" ? "Clean" : "Suspicious File";

  const base = { target: fileName, scanType: "file" as const, host: hashes.sha256.slice(0, 16), fileName,
    size: bytes.length, fileType, hashes, verdict, threatScore, securityScore, attackProbability, confidence, category,
    entropy: Number(ent.toFixed(2)), strings: [...hitIocs, ...urlsInside].slice(0, 10), signals, vulns, intel };

  const ai = await explainScan("file", base, errors);

  return {
    ...base,
    recommendations: ai?.recommendations?.length
      ? ai.recommendations
      : [
          verdict === "safe" ? "No malware intelligence hits — keep the file under normal monitoring." : "Quarantine the file immediately.",
          `Block the SHA-256 hash ${hashes.sha256.slice(0, 16)}… on all endpoints.`,
          "Detonate the file in an isolated sandbox before any user opens it.",
          "Check mail and proxy logs for other copies of this file.",
        ],
    explanation: ai?.explanation ?? undefined,
    durationMs: Date.now() - started,
    probeErrors: errors,
  };
}
