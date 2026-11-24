import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { AttackMap } from "@/components/attack-map";
import { PageHeader } from "@/components/ui-bits";

export const Route = createFileRoute("/map")({
  head: () => ({
    meta: [
      { title: "Live Attack Map — Sentinel OSINT" },
      { name: "description", content: "Real-time global cyber attack map showing origins, targets, and threat types." },
    ],
  }),
  component: () => <AppShell><MapPage /></AppShell>,
});

function MapPage() {
  return (
    <>
      <PageHeader kicker="Live Global Feed" title="Cyber Attack Map" subtitle="Real-time attack origins, target countries, and threat categories." />
      <div className="h-[70vh]"><AttackMap /></div>
    </>
  );
}
