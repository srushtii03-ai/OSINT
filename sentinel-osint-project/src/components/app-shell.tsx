import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import {
  Shield, LayoutDashboard, Search, Bug, Globe, Server,
  FileWarning, Mail, Key, Map, MessageSquare, Chrome, Menu, X, Bell, User
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

const nav = [
  { to: "/dashboard", label: "SOC Dashboard", icon: LayoutDashboard },
  { to: "/scanner", label: "URL Scanner", icon: Search },
  { to: "/cve", label: "CVE Database", icon: Bug },
  { to: "/domain", label: "Domain Intel", icon: Globe },
  { to: "/ip", label: "IP Intel", icon: Server },
  { to: "/file", label: "File Scanner", icon: FileWarning },
  { to: "/email", label: "Email Analyzer", icon: Mail },
  { to: "/breach", label: "Breach Check", icon: Key },
  { to: "/map", label: "Attack Map", icon: Map },
  { to: "/chat", label: "AI Analyst", icon: MessageSquare },
  { to: "/extension", label: "Browser Ext", icon: Chrome },
];

export function AppShell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const path = useRouterState({ select: (s) => s.location.pathname });

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside
        className={cn(
          "fixed lg:sticky top-0 left-0 z-40 h-screen w-64 shrink-0 glass border-r border-border/60 transition-transform",
          open ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        )}
      >
        <div className="flex items-center gap-2 px-5 h-16 border-b border-border/60">
          <div className="relative">
            <Shield className="h-7 w-7 text-primary" />
            <div className="absolute inset-0 rounded-full pulse-ring bg-primary/30" />
          </div>
          <div className="leading-tight">
            <div className="font-bold text-sm tracking-wider">SENTINEL/OSINT</div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-widest">Threat Intel v4.2</div>
          </div>
        </div>
        <nav className="p-3 space-y-1 overflow-y-auto h-[calc(100vh-4rem)]">
          {nav.map((item) => {
            const active = path.startsWith(item.to);
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setOpen(false)}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all group",
                  active
                    ? "bg-primary/15 text-primary neon-border"
                    : "text-muted-foreground hover:text-foreground hover:bg-secondary/60"
                )}
              >
                <Icon className={cn("h-4 w-4", active && "text-primary")} />
                <span>{item.label}</span>
                {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary animate-flicker" />}
              </Link>
            );
          })}
          <div className="pt-4 mt-4 border-t border-border/60 text-[10px] text-muted-foreground uppercase tracking-widest px-3">
            System Status
          </div>
          <div className="px-3 py-2 space-y-1 text-xs">
            <div className="flex justify-between"><span className="text-muted-foreground">Feed Latency</span><span className="text-safe">12ms</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">AI Model</span><span className="text-primary">SHAP v3</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Sources</span><span className="text-neon">16/16</span></div>
          </div>
        </nav>
      </aside>

      {/* Content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="sticky top-0 z-30 h-16 border-b border-border/60 glass flex items-center px-4 gap-3">
          <button className="lg:hidden" onClick={() => setOpen(!open)}>
            {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="h-2 w-2 rounded-full bg-safe animate-flicker" />
            <span className="uppercase tracking-widest">Live · Global Feed Active</span>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <Link to="/" className="text-xs text-muted-foreground hover:text-foreground">← Landing</Link>
            <button className="relative p-2 rounded-md hover:bg-secondary/60">
              <Bell className="h-4 w-4" />
              <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-critical animate-flicker" />
            </button>
            <div className="flex items-center gap-2 pl-3 border-l border-border/60">
              <div className="h-8 w-8 rounded-full bg-gradient-to-br from-primary to-cyber flex items-center justify-center">
                <User className="h-4 w-4 text-primary-foreground" />
              </div>
              <div className="text-xs leading-tight hidden sm:block">
                <div className="font-medium">SOC Analyst</div>
                <div className="text-muted-foreground">Tier 3 · Verified</div>
              </div>
            </div>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-6 max-w-full">{children ?? <Outlet />}</main>
      </div>

      {open && (
        <div className="fixed inset-0 bg-background/60 z-30 lg:hidden" onClick={() => setOpen(false)} />
      )}
    </div>
  );
}
