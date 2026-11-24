import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { SectionHeader, SeverityBadge } from "@/components/ui-bits";
import { Radar } from "lucide-react";

type Alert = {
  id: string;
  severity: string;
  title: string;
  message: string | null;
  target: string | null;
  created_at: string;
};

export function LiveAlerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let active = true;
    supabase
      .from("alerts")
      .select("id, severity, title, message, target, created_at")
      .order("created_at", { ascending: false })
      .limit(15)
      .then(({ data }) => { if (active && data) setAlerts(data as Alert[]); });

    const channel = supabase
      .channel("live-alerts")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "alerts" }, (payload) => {
        setAlerts((prev) => [payload.new as Alert, ...prev].slice(0, 15));
      })
      .subscribe((status) => setConnected(status === "SUBSCRIBED"));

    return () => { active = false; supabase.removeChannel(channel); };
  }, []);

  return (
    <div className="glass rounded-lg p-5 h-full">
      <SectionHeader
        title="Live Alert Stream"
        subtitle={connected ? "Realtime — updates the moment a scan flags a threat" : "Connecting to the live stream…"}
        right={<Radar className={`h-4 w-4 ${connected ? "text-safe animate-flicker" : "text-muted-foreground"}`} />}
      />
      {alerts.length === 0 ? (
        <div className="text-xs text-muted-foreground py-6 text-center">
          No alerts yet. Run a scan on a risky URL and it will appear here instantly.
        </div>
      ) : (
        <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
          {alerts.map((a) => (
            <div key={a.id} className="flex gap-3 p-2 rounded bg-secondary/40 text-xs">
              <SeverityBadge level={a.severity} />
              <div className="min-w-0 flex-1">
                <div className="font-medium truncate">{a.title}</div>
                <div className="text-muted-foreground truncate font-mono">{a.target}</div>
              </div>
              <div className="text-[10px] text-muted-foreground whitespace-nowrap">
                {new Date(a.created_at).toLocaleTimeString()}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
