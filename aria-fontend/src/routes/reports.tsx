import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Download, FileCode, FileText, FileSearch, Plus } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { EmptyState } from "@/components/ui/empty-state";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { Button } from "@/components/ui/button";
import { downloadReport, getAllScans } from "@/lib/api";
import { mockScanHistory } from "@/lib/mock";
import type { ScanResult } from "@/lib/types";
import { toast } from "sonner";

export const Route = createFileRoute("/reports")({
  component: ReportsPage,
});

function ReportsPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [isMock, setIsMock] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await getAllScans();
        if (!cancelled) {
          setScans(data.filter((s) => s.status === "completed"));
          setIsMock(false);
        }
      } catch {
        if (!cancelled) {
          setScans(mockScanHistory.filter((s) => s.status === "completed"));
          setIsMock(true);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleDownload = async (
    scan: ScanResult,
    format: "html" | "markdown",
  ) => {
    const key = `${scan.scan_id}-${format}`;
    setBusy(key);
    try {
      const blob = await downloadReport(scan.scan_id, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aria-report-${scan.scan_id}.${format === "html" ? "html" : "md"}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Downloaded ${format.toUpperCase()} report`);
    } catch {
      toast.error("Report download failed (backend unavailable)");
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <TopBar
        title="Reports"
        subtitle="Download HTML or Markdown reports for completed scans"
        actions={
          isMock && (
            <span className="rounded border border-warning/40 bg-warning/10 px-2 py-0.5 font-mono text-[10px] text-warning">
              MOCK
            </span>
          )
        }
      />
      <PageContainer>
        {loading ? (
          <div className="glass rounded-lg p-12 text-center text-xs text-muted-foreground">
            Loading completed scans…
          </div>
        ) : scans.length === 0 ? (
          <EmptyState
            icon={FileSearch}
            title="No reports available"
            description="Reports appear here once a scan completes successfully."
            action={
              <Button asChild size="sm">
                <Link to="/scan/new">
                  <Plus className="mr-1.5 h-3.5 w-3.5" />
                  New Scan
                </Link>
              </Button>
            }
          />
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {scans.map((s) => (
              <div
                key={s.scan_id}
                className="glass flex flex-col gap-3 rounded-lg p-4"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-sm text-foreground">
                      {s.target}
                    </div>
                    <div className="font-mono text-[10px] text-muted-foreground">
                      {s.scan_id}
                    </div>
                  </div>
                  <span className="rounded border border-success/40 bg-success/10 px-1.5 py-0.5 font-mono text-[10px] uppercase text-success">
                    completed
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 border-y border-border py-2 text-center font-mono text-[11px]">
                  <div>
                    <div className="text-muted-foreground">Findings</div>
                    <div className="text-warning tabular-nums">
                      {s.summary.findings_count}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Endpoints</div>
                    <div className="tabular-nums text-foreground">
                      {s.summary.total_endpoints}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Tasks</div>
                    <div className="tabular-nums text-foreground">
                      {s.summary.completed_tasks}
                    </div>
                  </div>
                </div>
                <div className="text-[10px] text-muted-foreground">
                  {new Date(s.timestamp).toLocaleString()}
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="flex-1"
                    disabled={busy === `${s.scan_id}-html`}
                    onClick={() => handleDownload(s, "html")}
                  >
                    <FileCode className="mr-1.5 h-3.5 w-3.5" />
                    HTML
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="flex-1"
                    disabled={busy === `${s.scan_id}-markdown`}
                    onClick={() => handleDownload(s, "markdown")}
                  >
                    <FileText className="mr-1.5 h-3.5 w-3.5" />
                    Markdown
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
        {!loading && scans.length > 0 && (
          <div className="mt-4 flex items-center gap-2 text-[10px] text-muted-foreground">
            <Download className="h-3 w-3" />
            Reports are generated server-side at /scan/:id/report
          </div>
        )}
      </PageContainer>
    </>
  );
}
