import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export function SeverityBadge({ level, className, children }: { level: string; className?: string; children?: ReactNode }) {
  const map: Record<string, string> = {
    critical: "bg-critical/20 text-critical border-critical/40",
    high: "bg-high/20 text-high border-high/40",
    medium: "bg-medium/20 text-medium border-medium/40",
    low: "bg-low/20 text-low border-low/40",
    safe: "bg-safe/20 text-safe border-safe/40",
    pass: "bg-safe/20 text-safe border-safe/40",
    warn: "bg-medium/20 text-medium border-medium/40",
    fail: "bg-critical/20 text-critical border-critical/40",
    malicious: "bg-critical/20 text-critical border-critical/40",
    suspicious: "bg-medium/20 text-medium border-medium/40",
  };
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border",
      map[level.toLowerCase()] ?? "bg-muted text-muted-foreground border-border",
      className
    )}>
      {children ?? level}
    </span>
  );
}

export function StatCard({ label, value, delta, icon, tone = "primary" }: {
  label: string; value: ReactNode; delta?: string; icon: ReactNode;
  tone?: "primary" | "critical" | "high" | "medium" | "low" | "safe" | "cyber";
}) {
  const toneMap: Record<string, string> = {
    primary: "from-primary/30 to-primary/5 text-primary",
    critical: "from-critical/30 to-critical/5 text-critical",
    high: "from-high/30 to-high/5 text-high",
    medium: "from-medium/30 to-medium/5 text-medium",
    low: "from-low/30 to-low/5 text-low",
    safe: "from-safe/30 to-safe/5 text-safe",
    cyber: "from-cyber/30 to-cyber/5 text-cyber",
  };
  return (
    <div className="glass rounded-lg p-4 relative overflow-hidden group">
      <div className={cn("absolute -right-6 -top-6 h-24 w-24 rounded-full bg-gradient-to-br opacity-40 blur-2xl", toneMap[tone])} />
      <div className="flex items-start justify-between relative">
        <div>
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
          <div className="mt-2 text-3xl font-bold tabular-nums">{value}</div>
          {delta && <div className={cn("text-xs mt-1", toneMap[tone])}>{delta}</div>}
        </div>
        <div className={cn("h-9 w-9 rounded-md flex items-center justify-center bg-gradient-to-br", toneMap[tone])}>
          {icon}
        </div>
      </div>
    </div>
  );
}

export function SectionHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: ReactNode }) {
  return (
    <div className="flex items-end justify-between gap-4 mb-4">
      <div>
        <h2 className="text-lg font-bold tracking-tight">{title}</h2>
        {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}

export function PageHeader({ title, subtitle, kicker, right }: { title: string; subtitle?: string; kicker?: string; right?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        {kicker && <div className="text-[10px] uppercase tracking-[0.25em] text-primary mb-2">{kicker}</div>}
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-muted-foreground mt-1 max-w-2xl">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}
