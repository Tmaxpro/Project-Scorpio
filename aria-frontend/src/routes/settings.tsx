import { useEffect, useState, useCallback } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  Loader2,
  RefreshCw,
  Server,
  Settings,
  WifiOff,
  HardDrive,
  Cpu,
  Check,
  AlertTriangle,
  Thermometer,
  Hash,
  Layers,
  Save,
  Zap,
  ZapOff,
  MemoryStick,
} from "lucide-react";
import { getModelsConfig, getAvailableModels, updateModel, getRunningModels, unloadModel } from "@/lib/api";
import type { ModelRole, ModelsResponse, OllamaModelInfo, RunningModelInfo } from "@/lib/types";
import { MODEL_ROLE_META } from "@/lib/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
});

const ROLE_ORDER: ModelRole[] = ["reasoning_model", "instruct_model", "fallback_model"];

type DraftRole = {
  name: string;
  temperature: number;
  max_tokens: number;
  use_for: string[];
};

type SaveState = "idle" | "saving" | "saved" | "error";

function shortName(n: string) {
  return n.includes("/")
    ? (n.split("/").pop() ?? n).replace(/-GGUF$/, "").replace(/[-_]Q\d.*$/, "")
    : n;
}

function SettingsPage() {
  const [config, setConfig] = useState<ModelsResponse | null>(null);
  const [available, setAvailable] = useState<OllamaModelInfo[]>([]);
  const [running, setRunning] = useState<RunningModelInfo[]>([]);

  const [loadingConfig, setLoadingConfig] = useState(true);
  const [loadingModels, setLoadingModels] = useState(true);
  const [configError, setConfigError] = useState<string | null>(null);
  const [ollamaError, setOllamaError] = useState<string | null>(null);
  const [unloading, setUnloading] = useState<string | null>(null);

  // Per-role draft state
  const [drafts, setDrafts] = useState<Record<ModelRole, DraftRole>>({
    reasoning_model: { name: "", temperature: 0.2, max_tokens: 2048, use_for: [] },
    instruct_model: { name: "", temperature: 0.1, max_tokens: 1024, use_for: [] },
    fallback_model: { name: "", temperature: 0.1, max_tokens: 2048, use_for: [] },
  });

  const [saveState, setSaveState] = useState<Record<ModelRole, SaveState>>({
    reasoning_model: "idle",
    instruct_model: "idle",
    fallback_model: "idle",
  });
  const [saveErrors, setSaveErrors] = useState<Record<ModelRole, string>>({
    reasoning_model: "",
    instruct_model: "",
    fallback_model: "",
  });

  const fetchConfig = useCallback(async () => {
    setLoadingConfig(true);
    setConfigError(null);
    try {
      const res = await getModelsConfig();
      setConfig(res);
      setDrafts({
        reasoning_model: { ...res.models.reasoning_model },
        instruct_model: { ...res.models.instruct_model },
        fallback_model: { ...res.models.fallback_model },
      });
    } catch (err) {
      setConfigError(err instanceof Error ? err.message : "Failed to load model configuration");
    } finally {
      setLoadingConfig(false);
    }
  }, []);

  const fetchModels = useCallback(async () => {
    setLoadingModels(true);
    setOllamaError(null);
    try {
      const [availRes, runRes] = await Promise.allSettled([
        getAvailableModels(),
        getRunningModels(),
      ]);
      if (availRes.status === "fulfilled") setAvailable(availRes.value.models);
      else setOllamaError(availRes.reason instanceof Error ? availRes.reason.message : "Cannot reach Ollama");
      if (runRes.status === "fulfilled") setRunning(runRes.value.models);
    } finally {
      setLoadingModels(false);
    }
  }, []);

  const handleUnload = async (name: string) => {
    setUnloading(name);
    try {
      await unloadModel(name);
      await fetchModels();
    } finally {
      setUnloading(null);
    }
  };

  useEffect(() => {
    fetchConfig();
    fetchModels();
  }, [fetchConfig, fetchModels]);

  const handleSaveRole = async (role: ModelRole) => {
    const draft = drafts[role];
    setSaveState((s) => ({ ...s, [role]: "saving" }));
    setSaveErrors((e) => ({ ...e, [role]: "" }));
    try {
      await updateModel(role, {
        name: draft.name,
        temperature: draft.temperature,
        max_tokens: draft.max_tokens,
      });
      setSaveState((s) => ({ ...s, [role]: "saved" }));
      window.dispatchEvent(new CustomEvent("aria:models-updated"));
      setTimeout(() => {
        setSaveState((s) => ({ ...s, [role]: "idle" }));
        fetchConfig();
      }, 1500);
    } catch (err) {
      setSaveErrors((e) => ({
        ...e,
        [role]: err instanceof Error ? err.message : "Save failed",
      }));
      setSaveState((s) => ({ ...s, [role]: "error" }));
      setTimeout(() => setSaveState((s) => ({ ...s, [role]: "idle" })), 3000);
    }
  };

  const isDirty = (role: ModelRole): boolean => {
    if (!config) return false;
    const orig = config.models[role];
    const d = drafts[role];
    return d.name !== orig.name || d.temperature !== orig.temperature || d.max_tokens !== orig.max_tokens;
  };

  // Which role is each available model currently assigned to?
  const modelToRole = (name: string): ModelRole | null => {
    if (!config) return null;
    for (const role of ROLE_ORDER) {
      if (config.models[role]?.name === name) return role;
    }
    return null;
  };

  const runningInfo = (name: string): RunningModelInfo | null =>
    running.find((r) => r.name === name || r.name.startsWith(name.split(":")[0])) ?? null;

  const loading = loadingConfig || loadingModels;

  const colorMap: Record<string, { border: string; badge: string; dot: string }> = {
    cyan: {
      border: "border-cyan/40",
      badge: "bg-cyan/15 text-cyan",
      dot: "bg-cyan",
    },
    violet: {
      border: "border-violet/40",
      badge: "bg-violet/15 text-violet",
      dot: "bg-violet",
    },
    warning: {
      border: "border-warning/40",
      badge: "bg-warning/15 text-warning",
      dot: "bg-warning",
    },
  };

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      {/* Page Header */}
      <div className="mb-8 flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary glow-cyan">
            <Settings className="h-5 w-5" />
          </div>
          <div>
            <h1 className="font-mono text-xl font-bold tracking-tight text-foreground">
              Model Configuration
            </h1>
            <p className="mt-0.5 text-sm text-muted-foreground">
              See your Ollama models and assign them to ARIA pipeline roles
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => { fetchConfig(); fetchModels(); }}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 ui-label text-muted-foreground transition-colors hover:bg-surface-hover hover:text-foreground disabled:opacity-50"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* Provider Banner */}
      {config && (
        <div className="mb-8 flex flex-wrap items-center gap-4 rounded-lg border border-border bg-card/50 px-4 py-3">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-muted-foreground" />
            <span className="ui-label">Provider</span>
            <span className="font-mono text-xs font-medium text-foreground">{config.provider}</span>
          </div>
          <div className="h-4 w-px bg-border" />
          <div className="flex items-center gap-2">
            <span className="ui-label">Endpoint</span>
            <span className="font-mono text-xs text-foreground">{config.base_url}</span>
          </div>
          <div className="h-4 w-px bg-border" />
          <div className="flex items-center gap-2">
            <RefreshCw className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="ui-label">Max Retries</span>
            <span className="font-mono text-xs font-medium text-foreground">{config.max_retries}</span>
          </div>
        </div>
      )}

      {/* Error States */}
      {configError && (
        <div className="mb-6 flex flex-col items-center rounded-lg border border-danger/40 bg-danger/10 py-10">
          <WifiOff className="h-8 w-8 text-danger" />
          <p className="mt-3 font-mono text-sm text-danger">{configError}</p>
          <p className="mt-1 text-xs text-muted-foreground">Make sure the ARIA backend is running</p>
          <button
            type="button"
            onClick={fetchConfig}
            className="mt-4 inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 ui-label text-primary-foreground hover:opacity-90"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Retry
          </button>
        </div>
      )}

      {/* ── SECTION 1: Available Ollama models ───────────────────────────── */}
      <section className="mb-10">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-foreground">
              Available Ollama Models
            </h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              All models currently pulled on this machine
            </p>
          </div>
          {!loadingModels && (
            <div className="flex items-center gap-2">
              {running.length > 0 && (
                <span className="ui-chip ui-chip-sm ui-chip-pill border-success/30 bg-success/10 text-success">
                  <Zap className="h-3 w-3" />
                  {running.length} in VRAM
                </span>
              )}
              <span className="ui-chip ui-chip-sm ui-chip-pill ui-chip-muted">
                {available.length} pulled
              </span>
            </div>
          )}
        </div>

        {loadingModels && (
          <div className="flex items-center gap-3 rounded-lg border border-border bg-card/30 px-5 py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="font-mono text-xs">Querying Ollama…</span>
          </div>
        )}

        {ollamaError && !loadingModels && (
          <div className="flex items-center gap-3 rounded-lg border border-warning/40 bg-warning/10 px-5 py-4">
            <AlertTriangle className="h-4 w-4 shrink-0 text-warning" />
            <div>
              <p className="font-mono text-xs text-warning">{ollamaError}</p>
              <p className="mt-0.5 text-[11px] text-muted-foreground">
                You can still type model names manually in the role configuration below
              </p>
            </div>
          </div>
        )}

        {!loadingModels && !ollamaError && available.length === 0 && (
          <div className="rounded-lg border border-border bg-card/30 px-5 py-10 text-center">
            <HardDrive className="mx-auto h-8 w-8 text-muted-foreground/40" />
            <p className="mt-3 font-mono text-xs text-muted-foreground">No models found</p>
            <p className="mt-1 text-[11px] text-muted-foreground/60">
              Run <code className="rounded bg-card px-1 py-0.5">ollama pull &lt;model&gt;</code> to add models
            </p>
          </div>
        )}

        {!loadingModels && available.length > 0 && (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {available.map((m) => {
              const assignedRole = modelToRole(m.name);
              const meta = assignedRole ? MODEL_ROLE_META[assignedRole] : null;
              const ri = runningInfo(m.name);
              const isUnloading = unloading === m.name;
              return (
                <div
                  key={m.name}
                  className={cn(
                    "glass flex flex-col gap-3 rounded-lg p-4 transition-colors",
                    ri
                      ? "border-success/40"
                      : assignedRole
                        ? colorMap[meta!.color].border
                        : "border-border hover:border-border/80",
                  )}
                >
                  {/* Name row */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      {ri
                        ? <Zap className="h-4 w-4 shrink-0 text-success" />
                        : <HardDrive className="h-4 w-4 shrink-0 text-muted-foreground" />
                      }
                      <span className="truncate font-mono text-sm font-medium text-foreground" title={m.name}>
                        {shortName(m.name)}
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {ri && (
                        <span className="ui-chip ui-chip-xs ui-chip-pill bg-success/15 text-success font-bold">
                          <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" />
                          in VRAM
                        </span>
                      )}
                      {assignedRole && meta && (
                        <span
                          className={cn(
                            "ui-chip ui-chip-xs ui-chip-pill font-bold",
                            colorMap[meta.color].badge,
                          )}
                        >
                          <span className={cn("h-1.5 w-1.5 rounded-full", colorMap[meta.color].dot)} />
                          {meta.label}
                        </span>
                      )}
                    </div>
                  </div>

                  {m.name !== shortName(m.name) && (
                    <span className="truncate ui-meta text-muted-foreground/50" title={m.name}>
                      {m.name}
                    </span>
                  )}

                  {/* Tags */}
                  <div className="flex flex-wrap gap-2">
                    {m.parameter_size && (
                      <span className="ui-chip ui-chip-sm ui-chip-muted">
                        {m.parameter_size}
                      </span>
                    )}
                    {m.quantization && (
                      <span className="ui-chip ui-chip-sm ui-chip-muted">
                        {m.quantization}
                      </span>
                    )}
                    {m.size && (
                      <span className="ui-chip ui-chip-sm ui-chip-muted">
                        {m.size}
                      </span>
                    )}
                    {ri && (
                      <span className="ui-chip ui-chip-sm border-success/30 bg-success/10 text-success">
                        <MemoryStick className="h-3 w-3" />
                        {ri.size_vram} VRAM
                      </span>
                    )}
                  </div>

                  {/* Unload button — only when model is in VRAM */}
                  {ri && (
                    <button
                      type="button"
                      onClick={() => handleUnload(m.name)}
                      disabled={isUnloading}
                      className="mt-auto inline-flex items-center justify-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-1.5 ui-label text-warning transition-colors hover:bg-warning/20 disabled:opacity-50"
                    >
                      {isUnloading
                        ? <><Loader2 className="h-3 w-3 animate-spin" />Unloading…</>
                        : <><ZapOff className="h-3 w-3" />Unload from VRAM</>
                      }
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* ── SECTION 2: Role assignment ────────────────────────────────────── */}
      {config && !configError && (
        <section>
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-foreground">
              Role Assignment
            </h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Choose which model handles each ARIA pipeline role
            </p>
          </div>

          <div className="flex flex-col gap-5">
            {ROLE_ORDER.map((role) => {
              const meta = MODEL_ROLE_META[role];
              const draft = drafts[role];
              const dirty = isDirty(role);
              const ss = saveState[role];
              const colors = colorMap[meta.color];

              return (
                <div
                  key={role}
                  className={cn(
                    "glass rounded-xl border p-5 transition-colors",
                    colors.border,
                  )}
                >
                  {/* Role header */}
                  <div className="mb-4 flex items-center gap-3">
                    <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-lg", colors.badge)}>
                      <Cpu className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            "ui-chip ui-chip-sm ui-chip-pill font-bold",
                            colors.badge,
                          )}
                        >
                          <span className={cn("h-1.5 w-1.5 rounded-full", colors.dot)} />
                          {meta.label}
                        </span>
                        {dirty && (
                          <span className="ui-chip ui-chip-xs ui-chip-pill border-warning/40 bg-warning/10 text-warning">
                            unsaved changes
                          </span>
                        )}
                      </div>
                      <p className="mt-0.5 text-[11px] text-muted-foreground">{meta.description}</p>
                    </div>
                  </div>

                  <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
                    {/* Left: model picker + sliders */}
                    <div className="space-y-4">
                      {/* Model select */}
                      <div className="space-y-1.5">
                        <label className="flex items-center gap-1.5 ui-label">
                          <HardDrive className="h-3 w-3" />
                          Model
                        </label>
                        {!loadingModels && available.length > 0 ? (
                          <select
                            value={draft.name}
                            onChange={(e) =>
                              setDrafts((d) => ({ ...d, [role]: { ...d[role], name: e.target.value } }))
                            }
                            className="w-full cursor-pointer rounded-md border border-border bg-card px-3 py-2 font-mono text-sm text-foreground outline-none transition-colors focus:border-primary"
                          >
                            {/* Keep current value in list even if not in Ollama */}
                            {!available.some((m) => m.name === draft.name) && (
                              <option value={draft.name}>{draft.name} (current)</option>
                            )}
                            {available.map((m) => (
                              <option key={m.name} value={m.name}>
                                {m.name}
                                {m.parameter_size ? ` — ${m.parameter_size}` : ""}
                                {m.quantization ? ` ${m.quantization}` : ""}
                                {m.size ? ` (${m.size})` : ""}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <input
                            type="text"
                            value={draft.name}
                            onChange={(e) =>
                              setDrafts((d) => ({ ...d, [role]: { ...d[role], name: e.target.value } }))
                            }
                            placeholder="model name (e.g. qwen2.5:7b)"
                            className="w-full rounded-md border border-border bg-card px-3 py-2 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/40 focus:border-primary"
                          />
                        )}
                      </div>

                      {/* Temperature + Max Tokens inline */}
                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-1.5">
                          <label className="flex items-center justify-between">
                            <span className="flex items-center gap-1.5 ui-label">
                              <Thermometer className="h-3 w-3" />
                              Temp
                            </span>
                            <span className="font-mono text-xs tabular-nums text-foreground">
                              {draft.temperature.toFixed(2)}
                            </span>
                          </label>
                          <input
                            type="range"
                            min="0"
                            max="2"
                            step="0.05"
                            value={draft.temperature}
                            onChange={(e) =>
                              setDrafts((d) => ({
                                ...d,
                                [role]: { ...d[role], temperature: parseFloat(e.target.value) },
                              }))
                            }
                            className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-border outline-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-primary [&::-webkit-slider-thumb]:shadow-md"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <label className="flex items-center justify-between">
                            <span className="flex items-center gap-1.5 ui-label">
                              <Hash className="h-3 w-3" />
                              Tokens
                            </span>
                            <span className="font-mono text-xs tabular-nums text-foreground">
                              {draft.max_tokens.toLocaleString()}
                            </span>
                          </label>
                          <input
                            type="range"
                            min="128"
                            max="16384"
                            step="128"
                            value={draft.max_tokens}
                            onChange={(e) =>
                              setDrafts((d) => ({
                                ...d,
                                [role]: { ...d[role], max_tokens: parseInt(e.target.value) },
                              }))
                            }
                            className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-border outline-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-primary [&::-webkit-slider-thumb]:shadow-md"
                          />
                        </div>
                      </div>

                      {/* Use-for tags */}
                      {draft.use_for.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Layers className="h-3 w-3 text-muted-foreground" />
                          {draft.use_for.map((u) => (
                            <span
                              key={u}
                              className="ui-chip ui-chip-xs ui-chip-pill ui-chip-muted"
                            >
                              {u}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Save error */}
                      {ss === "error" && saveErrors[role] && (
                        <div className="flex items-center gap-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 font-mono text-[11px] text-danger">
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                          {saveErrors[role]}
                        </div>
                      )}
                    </div>

                    {/* Right: Save button */}
                    <div className="flex items-end">
                      <button
                        type="button"
                        onClick={() => handleSaveRole(role)}
                        disabled={!dirty || ss === "saving" || ss === "saved"}
                        className={cn(
                          "inline-flex h-10 items-center gap-2 rounded-md px-4 ui-label transition-all",
                          dirty && ss === "idle"
                            ? "bg-primary text-primary-foreground hover:opacity-90 glow-cyan"
                            : ss === "saved"
                              ? "bg-success/20 text-success cursor-default"
                              : ss === "error"
                                ? "border border-danger/40 bg-danger/10 text-danger cursor-default"
                                : "cursor-not-allowed border border-border bg-card text-muted-foreground",
                        )}
                      >
                        {ss === "saving" ? (
                          <><Loader2 className="h-3.5 w-3.5 animate-spin" />Saving…</>
                        ) : ss === "saved" ? (
                          <><Check className="h-3.5 w-3.5" />Saved</>
                        ) : (
                          <><Save className="h-3.5 w-3.5" />Apply</>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}
