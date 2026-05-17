import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Download,
  Loader2,
  Zap,
} from "lucide-react";
import { YamlEditor } from "@/components/scan/YamlEditor";
import { AccountSetupGuide } from "@/components/benchmark/AccountSetupGuide";
import { createScan, saveBenchmarkRunLocal } from "@/lib/api";
import {
  GROUND_TRUTH,
  GROUND_TRUTH_VERSION,
  TARGET_APIS,
} from "@/lib/benchmark-ground-truth";
import type {
  BenchmarkConfig,
  BenchmarkRun,
  BenchmarkTarget,
  MatchStrategy,
  ModelName,
  ScanRequest,
  TargetAPIConfig,
} from "@/lib/types";
import { cn } from "@/lib/utils";

interface BenchmarkLaunchFormProps {
  target: BenchmarkTarget;
}

const MODELS: { value: ModelName; label: string; hint: string }[] = [
  {
    value: "foundation-sec-reasoning",
    label: "Foundation-Sec only",
    hint: "Primary reasoning SLM",
  },
  { value: "qwen2.5", label: "Qwen2.5 (baseline)", hint: "Generic fallback model" },
  {
    value: "both",
    label: "Both — full comparison",
    hint: "Runs two sequential scans",
  },
];

export function BenchmarkLaunchForm({ target }: BenchmarkLaunchFormProps) {
  const navigate = useNavigate();
  const config = TARGET_APIS[target];

  const [baseUrl, setBaseUrl] = useState(config.default_base_url);
  const [yamlText, setYamlText] = useState("");
  const [yamlValid, setYamlValid] = useState(false);

  const [user1Token, setUser1Token] = useState("");
  const [user2Token, setUser2Token] = useState("");
  const [adminToken, setAdminToken] = useState("");

  const [scanContext, setScanContext] = useState("");
  const [modelsToTest, setModelsToTest] = useState<ModelName>("both");
  const [matchStrategy, setMatchStrategy] = useState<MatchStrategy>("relaxed");
  const [includeSecureMode, setIncludeSecureMode] = useState(false);
  const [secureModeOpen, setSecureModeOpen] = useState(false);

  const [loadingSpec, setLoadingSpec] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const filledTokens = useMemo(
    () => ({
      user1_token: !!user1Token.trim(),
      user2_token: !!user2Token.trim(),
      admin_token: !!adminToken.trim(),
    }),
    [user1Token, user2Token, adminToken],
  );

  const skippedCount = useMemo(() => {
    if (filledTokens.user2_token) return 0;
    return (GROUND_TRUTH[target] ?? []).filter((g) => g.requires_victim_account).length;
  }, [filledTokens.user2_token, target]);

  const canLaunch = yamlValid && filledTokens.user1_token && !submitting;

  const loadOfficialSpec = async () => {
    if (!config.openapi_spec.url) return;
    setLoadingSpec(true);
    try {
      const res = await fetch(config.openapi_spec.url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      setYamlText(text);
    } catch (err) {
      setSubmitError(
        `Failed to load spec: ${err instanceof Error ? err.message : "unknown"}. Copy/paste manually instead.`,
      );
    } finally {
      setLoadingSpec(false);
    }
  };

  const submit = async () => {
    if (!canLaunch) return;
    setSubmitting(true);
    setSubmitError(null);

    const runId = `bench_${target}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    // ScanRequest payload — uses primary user1 token. Backend currently supports
    // a single bearer token; user2/admin are stored locally for matching context.
    const scanPayload: ScanRequest = {
      openapi_yaml: yamlText,
      base_url: baseUrl.trim(),
      auth_type: "bearer",
      credentials: { token: user1Token.trim() },
      context: scanContext.trim() || undefined,
      owasp_categories: config.owasp_coverage,
    };

    try {
      const { scan_id } = await createScan(scanPayload);

      // Persist benchmark metadata (NEVER tokens)
      const runConfig: Omit<BenchmarkConfig, "accounts"> = {
        target,
        base_url: baseUrl.trim(),
        openapi_yaml: yamlText,
        scan_context: scanContext.trim(),
        models_to_test: modelsToTest,
        match_strategy: matchStrategy,
        include_secure_mode: includeSecureMode,
      };

      const run: BenchmarkRun = {
        run_id: runId,
        target,
        target_name: config.name,
        timestamp: new Date().toISOString(),
        status: "running",
        config: runConfig,
        ground_truth_version: GROUND_TRUTH_VERSION,
        results: [],
        summary: {
          winner: null,
          best_f1: 0,
          total_ground_truth: (GROUND_TRUTH[target] ?? []).length,
          owasp_fully_covered: [],
          owasp_partially_covered: [],
          owasp_missed: [],
        },
      };

      // Stash the scan_id → run_id mapping in run metadata via sessionStorage too
      saveBenchmarkRunLocal(run);
      window.sessionStorage.setItem(
        `aria:benchmark:scan:${runId}`,
        JSON.stringify({ scan_id, ground_truth_version: GROUND_TRUTH_VERSION }),
      );

      navigate({ to: "/benchmarks/$runId", params: { runId } });
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : "Failed to launch benchmark");
      setSubmitting(false);
    }
  };

  return (
    <div className="glass space-y-6 rounded-lg p-6">
      <SectionHeader
        title="Launch configuration"
        caption={`Target: ${config.name} — provide spec, tokens, and benchmark options.`}
      />

      {/* Base URL */}
      <Field label="Target base URL" required>
        <input
          type="url"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          placeholder={config.default_base_url}
          className={inputCls(false)}
        />
      </Field>

      {/* OpenAPI YAML */}
      <Field
        label="OpenAPI specification"
        required
        hint={
          config.openapi_spec.available
            ? "Click 'Load official spec' or paste/upload your own."
            : "This target has no official spec — paste a manually written one."
        }
      >
        <div className="space-y-2">
          {!config.openapi_spec.available && (
            <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 font-mono text-[10px] text-warning">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span>{config.openapi_spec.note}</span>
            </div>
          )}
          {config.openapi_spec.available && config.openapi_spec.url && (
            <button
              type="button"
              onClick={loadOfficialSpec}
              disabled={loadingSpec}
              className="inline-flex items-center gap-2 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
            >
              {loadingSpec ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Download className="h-3 w-3" />
              )}
              {loadingSpec ? "Loading..." : "Load official spec from GitHub"}
            </button>
          )}
          <YamlEditor
            value={yamlText}
            onChange={setYamlText}
            onValidityChange={setYamlValid}
          />
        </div>
      </Field>

      {/* Account setup guide */}
      <AccountSetupGuide
        accounts={config.required_accounts}
        filled={filledTokens}
      />

      {/* Token inputs */}
      <div className="space-y-3">
        <Field label="Primary user token" required>
          <input
            type="password"
            value={user1Token}
            onChange={(e) => setUser1Token(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIs..."
            className={inputCls(false)}
          />
        </Field>
        {config.required_accounts.some((a) => a.role === "user2") && (
          <Field
            label="Victim user token"
            hint={`Needed for BOLA/BFLA testing — ${skippedCount > 0 ? `${skippedCount} ground truth entries will be skipped without it` : "ok to leave empty"}`}
          >
            <input
              type="password"
              value={user2Token}
              onChange={(e) => setUser2Token(e.target.value)}
              placeholder="eyJhbGciOiJIUzI1NiIs..."
              className={inputCls(false)}
            />
          </Field>
        )}
        <Field
          label="Admin token"
          hint="Optional — for admin endpoint tests"
        >
          <input
            type="password"
            value={adminToken}
            onChange={(e) => setAdminToken(e.target.value)}
            placeholder="(optional)"
            className={inputCls(false)}
          />
        </Field>
      </div>

      {/* Scan context */}
      <Field
        label="Scan context"
        hint="Optional hints for the Coordinator SLM — admin URL prefixes, ID formats, etc."
      >
        <textarea
          value={scanContext}
          onChange={(e) => setScanContext(e.target.value)}
          rows={3}
          maxLength={1000}
          placeholder="All admin endpoints start with /admin. User IDs are sequential integers."
          className={cn(inputCls(false), "resize-none font-mono text-xs")}
        />
      </Field>

      {/* Models to test */}
      <Field label="Models to compare">
        <div className="grid gap-2 sm:grid-cols-3">
          {MODELS.map((m) => (
            <label
              key={m.value}
              className={cn(
                "cursor-pointer rounded-md border p-3 transition-colors",
                modelsToTest === m.value
                  ? "border-primary bg-primary/10"
                  : "border-border bg-card hover:bg-surface-hover",
              )}
            >
              <input
                type="radio"
                name="model"
                value={m.value}
                checked={modelsToTest === m.value}
                onChange={() => setModelsToTest(m.value)}
                className="sr-only"
              />
              <div className="font-mono text-xs text-foreground">{m.label}</div>
              <div className="mt-0.5 text-[10px] text-muted-foreground">{m.hint}</div>
            </label>
          ))}
        </div>
      </Field>

      {/* Match strategy */}
      <Field
        label="Match strategy"
        hint={
          matchStrategy === "strict"
            ? "Strict: same OWASP category AND exact endpoint match required."
            : "Relaxed: same category + endpoint path segments overlap (recommended)."
        }
      >
        <div className="inline-flex rounded-md border border-border bg-card p-0.5">
          {(["strict", "relaxed"] as const).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setMatchStrategy(s)}
              className={cn(
                "rounded px-4 py-1.5 font-mono text-[10px] uppercase tracking-widest transition-colors",
                matchStrategy === s
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </Field>

      {/* Secure mode (VAmPI only) */}
      {config.has_secure_mode && (
        <SecureModeToggle
          config={config}
          checked={includeSecureMode}
          onChange={setIncludeSecureMode}
          expanded={secureModeOpen}
          onToggle={() => setSecureModeOpen((v) => !v)}
        />
      )}

      {/* Submit */}
      {submitError && (
        <div className="rounded-md border border-danger/40 bg-danger/10 p-3 font-mono text-xs text-danger">
          {submitError}
        </div>
      )}

      <div className="flex items-center justify-between border-t border-border pt-4">
        <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          {!yamlValid && "Need valid OpenAPI spec · "}
          {!filledTokens.user1_token && "Need primary user token · "}
          {skippedCount > 0 && filledTokens.user1_token && yamlValid && (
            <span className="text-warning">
              {skippedCount} ground truth entries will be skipped
            </span>
          )}
          {yamlValid && filledTokens.user1_token && skippedCount === 0 && (
            <span className="text-success">Ready to launch</span>
          )}
        </div>
        <button
          type="button"
          onClick={submit}
          disabled={!canLaunch}
          className={cn(
            "inline-flex items-center gap-2 rounded-md px-5 py-2.5 font-mono text-xs font-bold uppercase tracking-widest transition-all",
            canLaunch
              ? "bg-primary text-primary-foreground glow-cyan hover:opacity-90"
              : "cursor-not-allowed bg-muted text-muted-foreground",
          )}
        >
          {submitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Launching...
            </>
          ) : (
            <>
              <Zap className="h-4 w-4" />
              Launch benchmark
            </>
          )}
        </button>
      </div>
    </div>
  );
}

function SecureModeToggle({
  config,
  checked,
  onChange,
  expanded,
  onToggle,
}: {
  config: TargetAPIConfig;
  checked: boolean;
  onChange: (v: boolean) => void;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="rounded-md border border-border bg-card/40 p-4">
      <label className="flex cursor-pointer items-start gap-3">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          className="mt-0.5 h-4 w-4 cursor-pointer accent-primary"
        />
        <div className="min-w-0 flex-1">
          <div className="font-mono text-xs text-foreground">
            Include secure mode scan (false positive measurement)
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground">
            {config.secure_mode_note}
          </p>
          {config.docker_setup.secure_mode && (
            <button
              type="button"
              onClick={onToggle}
              className="mt-2 inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest text-primary hover:underline"
            >
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              Show secure mode docker command
            </button>
          )}
          {expanded && config.docker_setup.secure_mode && (
            <pre className="mt-2 overflow-x-auto rounded border border-border bg-background px-2 py-1.5 font-mono text-[10px] text-foreground">
              {config.docker_setup.secure_mode}
            </pre>
          )}
        </div>
      </label>
    </div>
  );
}

function SectionHeader({ title, caption }: { title: string; caption: string }) {
  return (
    <div>
      <div className="font-mono text-[10px] uppercase tracking-widest text-primary">
        Step 2
      </div>
      <h2 className="mt-1 text-xl font-semibold text-foreground">{title}</h2>
      <p className="text-sm text-muted-foreground">{caption}</p>
    </div>
  );
}

function Field({
  label,
  hint,
  error,
  required,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {label}
        {required && <span className="text-danger">*</span>}
      </label>
      {children}
      {error ? (
        <p className="font-mono text-[11px] text-danger">{error}</p>
      ) : hint ? (
        <p className="text-[11px] text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  );
}

function inputCls(error: boolean) {
  return cn(
    "w-full rounded-md border bg-[oklch(0.12_0.02_260)] px-3 py-2 text-sm text-foreground outline-none transition-colors placeholder:text-muted-foreground/50",
    error
      ? "border-danger/60 focus:border-danger"
      : "border-border focus:border-primary",
  );
}
