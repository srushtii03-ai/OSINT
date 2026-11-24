import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader, SeverityBadge } from "@/components/ui-bits";
import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useMutation } from "@tanstack/react-query";
import { scanFileFn } from "@/lib/scan.functions";
import type { FileReport } from "@/lib/file-scan.server";
import { UploadCloud, Loader2, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";

export const Route = createFileRoute("/file")({
  head: () => ({
    meta: [
      { title: "File Malware Scanner — Sentinel OSINT" },
      { name: "description", content: "Hash any file and check it against VirusTotal and MalwareBazaar, plus static indicators like packing, macros and double extensions." },
      { property: "og:title", content: "File Malware Scanner — Sentinel OSINT" },
      { property: "og:description", content: "Real hash-based malware intelligence with explainable scoring." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <AppShell><FileScanner /></AppShell>,
});

const MAX_BYTES = 8 * 1024 * 1024; // 8 MB keeps the request small enough to send safely

/** Turns raw file bytes into base64 text so we can send them as JSON. */
function toBase64(bytes: Uint8Array) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(binary);
}

function FileScanner() {
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<FileReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const scan = useServerFn(scanFileFn);

  const mutation = useMutation({
    mutationFn: async (f: File) => {
      if (f.size > MAX_BYTES) throw new Error("File is larger than 8 MB.");
      const bytes = new Uint8Array(await f.arrayBuffer());
      return scan({ data: { fileName: f.name, contentBase64: toBase64(bytes) } });
    },
    onSuccess: (res) => { setReport(res.report as FileReport); setErr(null); },
    onError: (e: Error) => { setErr(e.message); setReport(null); },
  });

  return (
    <>
      <PageHeader
        kicker="Malware"
        title="File Scanner"
        subtitle="The file is fingerprinted (hashed) and checked against VirusTotal and MalwareBazaar. It is never executed."
      />

      <label className="glass rounded-lg p-10 border-2 border-dashed border-border/80 flex flex-col items-center justify-center cursor-pointer hover:border-primary text-center">
        <UploadCloud className="h-10 w-10 text-primary mb-3" />
        <div className="font-semibold">{file ? file.name : "Drop a file or click to upload"}</div>
        <div className="text-xs text-muted-foreground mt-1">Max 8 MB · SHA-256, SHA-1 and MD5 are computed before any lookup</div>
        <input
          type="file"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0] ?? null;
            setFile(f);
            setReport(null);
            if (f) mutation.mutate(f);
          }}
        />
      </label>

      {mutation.isPending && (
        <div className="glass rounded-lg p-10 text-center mt-6">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <div className="mt-4 text-sm text-muted-foreground">Hashing file · querying VirusTotal + MalwareBazaar · analysing content…</div>
        </div>
      )}

      {err && !mutation.isPending && (
        <div className="glass rounded-lg p-5 mt-6 border-l-4 border-critical text-sm">
          <span className="text-critical font-bold">Scan failed. </span>{err}
        </div>
      )}

      {report && !mutation.isPending && <FileResult r={report} />}
    </>
  );
}

function FileResult({ r }: { r: FileReport }) {
  const Icon = r.verdict === "safe" ? ShieldCheck : r.verdict === "suspicious" ? ShieldAlert : ShieldX;
  const tone = r.verdict === "safe" ? "text-safe" : r.verdict === "suspicious" ? "text-medium" : "text-critical";
  const border = r.verdict === "safe" ? "border-safe" : r.verdict === "suspicious" ? "border-medium" : "border-critical";

  return (
    <div className="space-y-6 mt-6">
      <div className={`glass rounded-lg p-6 border-l-4 ${border} flex flex-wrap items-center gap-5`}>
        <Icon className={`h-12 w-12 ${tone}`} />
        <div className="flex-1 min-w-0">
          <div className="text-xs uppercase tracking-widest text-muted-foreground">{r.fileType} · {(r.size / 1024).toFixed(1)} KB · {(r.durationMs / 1000).toFixed(1)}s</div>
          <div className="font-mono text-sm truncate">{r.fileName}</div>
          <div className="mt-2 flex items-center gap-3 flex-wrap">
            <SeverityBadge level={r.verdict} />
            <span className="text-xs text-muted-foreground">Category: <span className="text-foreground">{r.category}</span></span>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Metric label="Threat" value={r.threatScore} className={tone} />
          <Metric label="Security" value={r.securityScore} className="text-safe" />
          <Metric label="Attack Prob." value={`${r.attackProbability}%`} className="text-high" />
          <Metric label="Confidence" value={`${r.confidence}%`} className="neon-text" />
        </div>
      </div>

      {r.explanation && (
        <div className="glass rounded-lg p-5">
          <SectionHeader title="AI Explanation" subtitle="Based on the hash reputation and the file's own content" />
          <p className="text-sm leading-relaxed">{r.explanation}</p>
        </div>
      )}

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="glass rounded-lg p-5">
          <SectionHeader title="File Hashes" subtitle="A hash is a unique fingerprint of the file" />
          <dl className="text-xs space-y-2 font-mono">
            <div><dt className="text-[10px] uppercase text-muted-foreground">SHA-256</dt><dd className="break-all">{r.hashes.sha256}</dd></div>
            <div><dt className="text-[10px] uppercase text-muted-foreground">SHA-1</dt><dd className="break-all">{r.hashes.sha1}</dd></div>
            <div><dt className="text-[10px] uppercase text-muted-foreground">MD5</dt><dd className="break-all">{r.hashes.md5}</dd></div>
            <div><dt className="text-[10px] uppercase text-muted-foreground">Entropy</dt><dd>{r.entropy} / 8</dd></div>
          </dl>
        </div>

        <div className="glass rounded-lg p-5 lg:col-span-2">
          <SectionHeader title="Feature Attribution" subtitle="How much each finding pushed the score" />
          <div className="space-y-3">
            {r.signals.map((s) => (
              <div key={s.name}>
                <div className="flex justify-between text-xs mb-1">
                  <span>{s.name} <span className="text-muted-foreground">· {s.detail}</span></span>
                  <span className={s.direction === "risk" ? "text-critical" : "text-safe"}>
                    {s.direction === "risk" ? "+" : "−"}{Math.abs(s.weight)}
                  </span>
                </div>
                <div className="h-2 rounded bg-secondary overflow-hidden">
                  <div className={`h-full ${s.direction === "risk" ? "bg-critical" : "bg-safe"}`} style={{ width: `${Math.min(100, Math.abs(s.weight) * 2.5)}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="glass rounded-lg p-5">
          <SectionHeader title="OSINT Source Verdicts" />
          <div className="space-y-2">
            {r.intel.map((s) => (
              <div key={s.source} className="flex items-center justify-between p-2 rounded bg-secondary/40 text-xs gap-3">
                <span className="font-semibold">{s.source}</span>
                <span className={!s.enabled ? "text-muted-foreground" : s.hits > 0 ? "text-critical" : "text-safe"}>{s.verdict}</span>
              </div>
            ))}
          </div>
          {r.strings.length > 0 && (
            <>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-4 mb-2">Indicators found inside the file</div>
              <div className="flex flex-wrap gap-1.5">
                {r.strings.map((s) => <span key={s} className="px-2 py-0.5 rounded border border-border text-[10px] truncate max-w-full">{s}</span>)}
              </div>
            </>
          )}
        </div>

        <div className="glass rounded-lg p-5">
          <SectionHeader title="Checks" />
          <table className="w-full text-xs">
            <tbody>
              {r.vulns.map((v) => (
                <tr key={v.name} className="border-b border-border/30 align-top">
                  <td className="py-2 font-medium">{v.name}</td>
                  <td><SeverityBadge level={v.status} /></td>
                  <td className="text-muted-foreground">{v.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="glass rounded-lg p-5">
        <SectionHeader title="Recommended Actions" />
        <ul className="space-y-2 text-sm">
          {r.recommendations.map((rec, i) => (
            <li key={i} className="flex gap-3">
              <span className="h-6 w-6 shrink-0 rounded-full bg-secondary flex items-center justify-center text-xs font-bold">{i + 1}</span>
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      </div>

      {r.probeErrors.length > 0 && (
        <div className="glass rounded-lg p-4 text-[11px] text-muted-foreground">
          <span className="uppercase tracking-widest">Probe notes:</span> {r.probeErrors.join(" · ")}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, className }: { label: string; value: string | number; className?: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={`text-3xl font-bold tabular-nums ${className ?? ""}`}>{value}</div>
    </div>
  );
}
