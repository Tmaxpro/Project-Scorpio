import { createFileRoute, Link } from "@tanstack/react-router";
import { Activity, Pause, Square } from "lucide-react";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { ScanDashboard } from "@/components/scan/ScanDashboard";
import { Button } from "@/components/ui/button";
import { useScanStream } from "@/lib/useScanStream";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/scan/$id")({
  component: ScanDashboardPage,
});

function ScanDashboardPage() {
  const { id } = Route.useParams();
  const state = useScanStream(id);

  const statusColor = {
    connecting: "text-muted-foreground",
    running: "text-cyan",
    completed: "text-success",
    failed: "text-[var(--sev-critical)]",
  }[state.status];

  return (
    <>
      <TopBar
        title={`Scan ${id}`}
        subtitle={state.scan.target}
        actions={
          <>
            <span
              className={cn(
                "flex items-center gap-1.5 ui-label",
                statusColor,
              )}
            >
              <Activity className="h-3.5 w-3.5 animate-pulse-dot" />
              {state.status}
            </span>
            <Button variant="outline" size="sm" disabled>
              <Pause className="mr-1.5 h-3.5 w-3.5" />
              Pause
            </Button>
            <Button variant="outline" size="sm" disabled>
              <Square className="mr-1.5 h-3.5 w-3.5" />
              Stop
            </Button>
            <Button asChild size="sm" variant="ghost">
              <Link to="/history">History</Link>
            </Button>
          </>
        }
      />
      <PageContainer className="flex h-[calc(100vh-56px)] flex-col overflow-hidden pb-6">
        <ScanDashboard scanId={id} />
      </PageContainer>
    </>
  );
}
