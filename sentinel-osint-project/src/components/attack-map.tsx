import { attackOrigins, attackTargets } from "@/lib/mock-data";
import { useEffect, useState } from "react";

// Lightweight SVG world silhouette (stylized dots) + animated attack arcs.
// Not geographically precise — designed for cyberpunk SOC visual.
export function AttackMap({ compact = false }: { compact?: boolean }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick(t => (t + 1) % 1000), 900);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="relative w-full h-full overflow-hidden rounded-lg bg-gradient-to-br from-background to-secondary/40 border border-border/60">
      <div className="absolute inset-0 opacity-40" style={{
        backgroundImage: "radial-gradient(circle at 1px 1px, var(--primary) 1px, transparent 0)",
        backgroundSize: "22px 22px",
      }} />
      <svg viewBox="0 0 100 60" className="absolute inset-0 w-full h-full" preserveAspectRatio="none">
        <defs>
          <linearGradient id="arc" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--critical)" stopOpacity="0.9" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0.2" />
          </linearGradient>
        </defs>
        {/* Continents stylized as dot clusters */}
        {CONTINENT_DOTS.map((d, i) => (
          <circle key={i} cx={d[0]} cy={d[1]} r="0.35" fill="var(--primary)" opacity="0.5" />
        ))}

        {/* Attack arcs */}
        {attackOrigins.map((o, i) => {
          const t = attackTargets[(i + tick) % attackTargets.length];
          const mx = (o.x + t.x) / 2;
          const my = Math.min(o.y, t.y) - 12;
          return (
            <g key={o.code}>
              <path d={`M${o.x} ${o.y} Q ${mx} ${my} ${t.x} ${t.y}`}
                fill="none" stroke="url(#arc)" strokeWidth="0.4" opacity="0.85">
                <animate attributeName="stroke-dasharray" values="0,60;60,0" dur="2.4s" repeatCount="indefinite" />
              </path>
              <circle cx={t.x} cy={t.y} r="0.9" fill="var(--critical)">
                <animate attributeName="r" values="0.9;2.4;0.9" dur="1.6s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="1;0;1" dur="1.6s" repeatCount="indefinite" />
              </circle>
            </g>
          );
        })}

        {/* Origin markers */}
        {attackOrigins.map(o => (
          <g key={"o" + o.code}>
            <circle cx={o.x} cy={o.y} r="1" fill="var(--neon)" />
            <circle cx={o.x} cy={o.y} r="1.6" fill="none" stroke="var(--neon)" strokeWidth="0.2">
              <animate attributeName="r" values="1.2;3;1.2" dur="2s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="1;0;1" dur="2s" repeatCount="indefinite" />
            </circle>
          </g>
        ))}
      </svg>

      {!compact && (
        <div className="absolute bottom-3 left-3 right-3 flex flex-wrap gap-2 text-[10px]">
          {attackOrigins.slice(0, 6).map(o => (
            <div key={o.code} className="glass px-2 py-1 rounded flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-critical animate-flicker" />
              <span className="font-bold">{o.country}</span>
              <span className="text-muted-foreground">{o.attacks.toLocaleString()} attacks</span>
            </div>
          ))}
        </div>
      )}
      <div className="absolute top-3 left-3 text-[10px] uppercase tracking-widest text-muted-foreground">
        Live Global Attack Feed
      </div>
      <div className="absolute top-3 right-3 text-[10px] uppercase tracking-widest text-safe flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-safe animate-flicker" /> Streaming
      </div>
    </div>
  );
}

// Rough continent silhouettes made from scattered dots
const CONTINENT_DOTS: [number, number][] = (() => {
  const pts: [number, number][] = [];
  const shapes = [
    // North America
    { cx: 22, cy: 32, rx: 10, ry: 12, n: 90 },
    // South America
    { cx: 30, cy: 55, rx: 6, ry: 10, n: 60 },
    // Europe
    { cx: 50, cy: 26, rx: 6, ry: 5, n: 55 },
    // Africa
    { cx: 52, cy: 45, rx: 7, ry: 10, n: 80 },
    // Asia
    { cx: 70, cy: 30, rx: 14, ry: 10, n: 130 },
    // Australia
    { cx: 82, cy: 55, rx: 5, ry: 4, n: 35 },
  ];
  for (const s of shapes) {
    for (let i = 0; i < s.n; i++) {
      const a = Math.random() * Math.PI * 2;
      const r = Math.sqrt(Math.random());
      pts.push([s.cx + Math.cos(a) * r * s.rx, s.cy + Math.sin(a) * r * s.ry]);
    }
  }
  return pts;
})();
