import { useCallback, useEffect, useRef, useState } from "react";
import { apiBaseUrl, getBenchmarkRunLocal, listBenchmarkRunsLocal, saveBenchmarkRunLocal } from "@/lib/api";
import { computeBenchmarkResults, computeRunSummary } from "@/lib/benchmark-matcher";
import type {
  BenchmarkRun,
  BenchmarkRunStatus,
  MatchStrategy,
  ModelName,
  ScanResult,
  Severity,
  TaskResult,
} from "@/lib/types";

/* ──────────────────────────────────────────────────────────────────────────
 *  Helpers — convert backend FindingSummary[] to frontend TaskResult[]
 * ────────────────────────────────────────────────────────────────────────── */

interface BackendFinding {
  task_id: string;
  endpoint: string;
  method?: string;
  vuln_category: string;
  owasp_ref?: string;
  severity: string;
  confidence?: string;
  is_vulnerable: boolean;
  rule_ids: string[];
  evidence: string;
  remediation?: string;
  confirmed_by_slm: boolean;
}

interface BackendResults {
  scan_id: string;
  status: string;
  total_requests: number;
  vulnerable_count: number;
  findings: BackendFinding[];
}

interface BackendStatus {
  scan_id: string;
  status: string;
  progress: number;
  message: string;
  target?: string;
  started_at?: string;
  finished_at?: string;
  findings_count?: number;
  vulnerable_count?: number;
  total_tasks?: number;
  completed_tasks?: number;
}

function asSeverity(s: string): Severity {
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") return s;
  return "info";
}

function asConfidence(c: string | undefined): TaskResult["confidence"] {
  if (c === "high" || c === "medium" || c === "low") return c;
  return "medium";
}

function backendFindingToTaskResult(bf: BackendFinding): TaskResult {
  return {
    task_id: bf.task_id,
    vuln_category: (bf.vuln_category as TaskResult["vuln_category"]) ?? "API8",
    endpoint: bf.endpoint,
    method: bf.method ?? "GET",
    finding: bf.is_vulnerable,
    severity: asSeverity(bf.severity),
    confidence: asConfidence(bf.confidence),
    evidence: {
      request: {
        method: bf.method ?? "GET",
        url: bf.endpoint,
        headers: {},
      },
      response: {
        status_code: 0,
        headers: {},
        body_excerpt: bf.evidence ?? "",
        elapsed_ms: 0,
      },
    },
    remediation: bf.remediation ?? "",
    owasp_ref: bf.owasp_ref ?? `${bf.vuln_category}:2023`,
    timestamp: new Date().toISOString(),
  };
}

function buildScanResult(status: BackendStatus, findings: TaskResult[]): ScanResult {
  return {
    scan_id: status.scan_id,
    status: "completed",
    target: status.target ?? "",
    findings,
    timestamp: status.finished_at ?? new Date().toISOString(),
    total_requests: findings.length,
    summary: {
      total_endpoints: 0,
      total_tasks: status.total_tasks ?? findings.length,
      completed_tasks: status.completed_tasks ?? findings.length,
      findings_count: findings.length,
      by_severity: countBySeverity(findings),
      by_category: countByCategory(findings),
    },
    model_usage_log: [],
  };
}

function countBySeverity(findings: TaskResult[]) {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function countByCategory(findings: TaskResult[]) {
  const cats = ["API1","API2","API3","API4","API5","API6","API7","API8","API9","API10"] as const;
  const out = Object.fromEntries(cats.map((c) => [c, 0])) as Record<TaskResult["vuln_category"], number>;
  for (const f of findings) out[f.vuln_category]++;
  return out;
}

/* ──────────────────────────────────────────────────────────────────────────
 *  useBenchmarkRun — poll scan status, compute metrics when done.
 * ────────────────────────────────────────────────────────────────────────── */

interface SessionMeta {
  scan_id: string;
  ground_truth_version: string;
}

interface UseBenchmarkRunResult {
  run: BenchmarkRun | null;
  isLoading: boolean;
  error: string | null;
  scanProgress: number;
  scanMessage: string;
  recompute: (strategy: MatchStrategy) => void;
}

export function useBenchmarkRun(runId: string): UseBenchmarkRunResult {
  const [run, setRun] = useState<BenchmarkRun | null>(() => getBenchmarkRunLocal(runId));
  const [error, setError] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanMessage, setScanMessage] = useState("Connecting...");
  const scanResultRef = useRef<ScanResult | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  // Re-apply matching with a new strategy — no API call.
  const recompute = useCallback(
    (strategy: MatchStrategy) => {
      const current = scanResultRef.current;
      const localRun = getBenchmarkRunLocal(runId);
      if (!current || !localRun) return;
      const primaryModel: ModelName =
        localRun.config.models_to_test === "qwen2.5" ? "qwen2.5" : "foundation-sec-reasoning";
      const newResult = computeBenchmarkResults(current, localRun.target, primaryModel, strategy);
      const newSummary = computeRunSummary([newResult], localRun.target);
      const updated: BenchmarkRun = {
        ...localRun,
        status: "completed",
        config: { ...localRun.config, match_strategy: strategy },
        results: [newResult],
        summary: { ...newSummary },
      };
      saveBenchmarkRunLocal(updated);
      setRun(updated);
    },
    [runId],
  );

  useEffect(() => {
    let cancelled = false;

    // Read scan_id from sessionStorage (set at launch time)
    const metaRaw = typeof window !== "undefined"
      ? window.sessionStorage.getItem(`aria:benchmark:scan:${runId}`)
      : null;
    const meta: SessionMeta | null = metaRaw ? JSON.parse(metaRaw) : null;

    const localRun = getBenchmarkRunLocal(runId);
    if (!localRun) {
      setError("Run not found");
      return;
    }
    setRun(localRun);

    // If already completed and we have results, nothing to poll.
    if (localRun.status === "completed" && localRun.results.length > 0) {
      return;
    }

    // Need scan_id to poll
    if (!meta?.scan_id) {
      // Run is in localStorage but scan_id has been lost (e.g. different tab).
      // We can still display the saved run; just no polling.
      return;
    }

    const finalize = async (status: BackendStatus) => {
      try {
        const res = await fetch(`${apiBaseUrl}/api/scan/${status.scan_id}/results`);
        if (!res.ok) throw new Error(`Results fetch failed: ${res.status}`);
        const data: BackendResults = await res.json();
        const findings = data.findings.map(backendFindingToTaskResult);
        const scan = buildScanResult(status, findings);
        scanResultRef.current = scan;

        const primaryModel: ModelName =
          localRun.config.models_to_test === "qwen2.5"
            ? "qwen2.5"
            : "foundation-sec-reasoning";
        const result = computeBenchmarkResults(
          scan,
          localRun.target,
          primaryModel,
          localRun.config.match_strategy,
        );
        const summary = computeRunSummary([result], localRun.target);

        const completed: BenchmarkRun = {
          ...localRun,
          scan_id: localRun.scan_id || meta.scan_id,
          status: "completed",
          results: [result],
          summary,
        };
        if (!cancelled) {
          saveBenchmarkRunLocal(completed);
          setRun(completed);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to compute results");
        }
      }
    };

    const poll = async () => {
      try {
        const res = await fetch(`${apiBaseUrl}/api/scan/${meta.scan_id}`);
        if (!res.ok) throw new Error(`Status fetch failed: ${res.status}`);
        const status: BackendStatus = await res.json();
        if (cancelled) return;
        setScanProgress(status.progress * 100);
        setScanMessage(status.message);

        if (status.status === "completed") {
          stopPolling();
          // Mark as computing while we fetch and crunch
          const computing: BenchmarkRun = { ...localRun, status: "computing" };
          saveBenchmarkRunLocal(computing);
          setRun(computing);
          await finalize(status);
        } else if (status.status === "failed") {
          stopPolling();
          const failed: BenchmarkRun = { ...localRun, status: "failed" };
          saveBenchmarkRunLocal(failed);
          if (!cancelled) {
            setRun(failed);
            setError(status.message || "Scan failed");
          }
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Polling error");
      }
    };

    const stopPolling = () => {
      if (pollTimer.current) {
        clearInterval(pollTimer.current);
        pollTimer.current = null;
      }
    };

    void poll();
    pollTimer.current = setInterval(poll, 2000);

    return () => {
      cancelled = true;
      stopPolling();
    };
  }, [runId]);

  const finalStatus: BenchmarkRunStatus | undefined = run?.status;
  const isLoading = finalStatus === "running" || finalStatus === "computing";

  return { run, isLoading, error, scanProgress, scanMessage, recompute };
}

/* ──────────────────────────────────────────────────────────────────────────
 *  useBenchmarkList — list all stored runs (refreshes every 3s).
 * ────────────────────────────────────────────────────────────────────────── */

export function useBenchmarkList(): { runs: BenchmarkRun[] } {
  const [runs, setRuns] = useState<BenchmarkRun[]>(() => listBenchmarkRunsLocal());

  useEffect(() => {
    const refresh = () => setRuns(listBenchmarkRunsLocal());
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, []);

  return { runs };
}
