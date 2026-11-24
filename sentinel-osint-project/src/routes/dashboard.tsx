import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionHeader, SeverityBadge, StatCard } from "@/components/ui-bits";
import { AttackMap } from "@/components/attack-map";
import { LiveAlerts } from "@/components/live-alerts";
import {
  threatStats, attackTrends, riskDistribution, topMalware, topActors, cves
} from "@/lib/mock-data";
import {
  AlertOctagon, AlertTriangle, ShieldAlert, ShieldCheck, Activity
} from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
  PieChart, Pie, Cell, Legend, BarChart, Bar
} from "recharts";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "SOC Dashboard — Sentinel OSINT" },
      { name: "description", content: "Live threat intelligence dashboard with critical alerts, attack trends, IOC feed, and global attack map." },
    ],
  }),
  component: () => <AppShell><Dashboard /></AppShell>,
});

function Dashboard() {
  return (
    <>
      <PageHeader
        kicker="SOC · Tier 3"
        title="Threat Intelligence Overview"
        subtitle="Live global picture. Streaming across 16 OSINT feeds and 4,820 monitored assets."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard label="Critical Threats" value={threatStats.critical} delta="+12 last hour" icon={<AlertOctagon className="h-5 w-5" />} tone="critical" />
        <StatCard label="High Threats" value={threatStats.high} delta="+34 last hour" icon={<AlertTriangle className="h-5 w-5" />} tone="high" />
        <StatCard label="Blocked Today" value={threatStats.blockedToday.toLocaleString()} delta="+8.4% vs yesterday" icon={<ShieldAlert className="h-5 w-5" />} tone="cyber" />
        <StatCard label="Assets Monitored" value={threatStats.monitoredAssets.toLocaleString()} delta="12 active incidents" icon={<ShieldCheck className="h-5 w-5" />} tone="safe" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-6">
        <div className="xl:col-span-2 glass rounded-lg p-5">
          <SectionHeader title="Attack Trends — Last 24h" subtitle="Detections per hour, grouped by threat family" right={<Activity className="h-4 w-4 text-primary" />} />
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={attackTrends}>
                <defs>
                  {["phishing","malware","ddos","ransomware"].map((k, i) => (
                    <linearGradient key={k} id={`g${i}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={`var(--chart-${i+1})`} stopOpacity={0.6} />
                      <stop offset="100%" stopColor={`var(--chart-${i+1})`} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" opacity={0.3} />
                <XAxis dataKey="hour" stroke="var(--muted-foreground)" fontSize={10} />
                <YAxis stroke="var(--muted-foreground)" fontSize={10} />
                <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", fontSize: 12 }} />
                <Area type="monotone" dataKey="phishing" stroke="var(--chart-1)" fill="url(#g0)" strokeWidth={2} />
                <Area type="monotone" dataKey="malware" stroke="var(--chart-2)" fill="url(#g1)" strokeWidth={2} />
                <Area type="monotone" dataKey="ddos" stroke="var(--chart-3)" fill="url(#g2)" strokeWidth={2} />
                <Area type="monotone" dataKey="ransomware" stroke="var(--chart-4)" fill="url(#g3)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass rounded-lg p-5">
          <SectionHeader title="Risk Distribution" subtitle="Currently active" />
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={riskDistribution} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={3}>
                  {riskDistribution.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Pie>
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-6">
        <div className="xl:col-span-2">
          <LiveAlerts />
        </div>


        <div className="glass rounded-lg p-5">
          <SectionHeader title="Top Malware Families" subtitle="Last 24h detections" />
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topMalware} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" opacity={0.3} horizontal={false} />
                <XAxis type="number" stroke="var(--muted-foreground)" fontSize={10} />
                <YAxis type="category" dataKey="name" stroke="var(--muted-foreground)" fontSize={10} width={110} />
                <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", fontSize: 12 }} />
                <Bar dataKey="count" fill="var(--chart-2)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 h-96">
          <AttackMap />
        </div>
        <div className="glass rounded-lg p-5">
          <SectionHeader title="Latest Critical CVEs" />
          <div className="space-y-3">
            {cves.filter(c => c.severity === "critical").slice(0, 4).map(c => (
              <div key={c.id} className="p-3 rounded-md bg-secondary/60 border border-border/60">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-primary text-xs">{c.id}</span>
                  <SeverityBadge level={c.severity} />
                </div>
                <div className="text-xs font-semibold">{c.product}</div>
                <div className="text-[11px] text-muted-foreground line-clamp-2 mt-1">{c.desc}</div>
                <div className="flex items-center justify-between mt-2 text-[10px] text-muted-foreground">
                  <span>CVSS {c.cvss}</span>
                  {c.exploit && <span className="text-critical">⚠ Exploit in the wild</span>}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-3 border-t border-border/60">
            <SectionHeader title="Top Threat Actors" />
            <div className="space-y-2">
              {topActors.slice(0, 4).map(a => (
                <div key={a.name} className="flex items-center justify-between text-xs">
                  <div>
                    <div className="font-semibold">{a.name}</div>
                    <div className="text-[10px] text-muted-foreground">{a.origin}</div>
                  </div>
                  <div className="text-primary font-mono">{a.campaigns}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
