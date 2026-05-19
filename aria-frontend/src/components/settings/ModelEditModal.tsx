import { useEffect, useState } from "react";
import { Loader2, Save, X, AlertTriangle, Check, HardDrive } from "lucide-react";
import { getAvailableModels, updateModel } from "@/lib/api";
import type { ModelConfig, ModelRole, OllamaModelInfo } from "@/lib/types";
import { MODEL_ROLE_META } from "@/lib/types";
import { cn } from "@/lib/utils";

interface ModelEditModalProps {
  role: ModelRole;
  current: ModelConfig;
  onClose: () => void;
  onSaved: () => void;
}

export function ModelEditModal({ role, current, onClose, onSaved }: ModelEditModalProps) {
  const meta = MODEL_ROLE_META[role];

  const [name, setName] = useState(current.name);
  const [temperature, setTemperature] = useState(current.temperature);
  const [maxTokens, setMaxTokens] = useState(current.max_tokens);

  const [available, setAvailable] = useState<OllamaModelInfo[]>([]);
  const [loadingModels, setLoadingModels] = useState(true);
  const [ollamaError, setOllamaError] = useState<string | null>(null);

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Fetch available Ollama models on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await getAvailableModels();
        if (!cancelled) {
          setAvailable(res.models);
          setOllamaError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setOllamaError(err instanceof Error ? err.message : "Failed to reach Ollama");
        }
      } finally {
        if (!cancelled) setLoadingModels(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      await updateModel(role, { name, temperature, max_tokens: maxTokens });
      setSaved(true);
      setTimeout(() => {
        onSaved();
        onClose();
      }, 600);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "Failed to update model");
    } finally {
      setSaving(false);
    }
  };

  const hasChanges =
    name !== current.name ||
    temperature !== current.temperature ||
    maxTokens !== current.max_tokens;

  const badgeBgMap: Record<string, string> = {
    cyan: "bg-cyan/15 text-cyan",
    violet: "bg-violet/15 text-violet",
    warning: "bg-warning/15 text-warning",
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative mx-4 w-full max-w-lg animate-in fade-in zoom-in-95 duration-200">
        <div className="glass overflow-hidden rounded-xl border border-border shadow-2xl">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <div className="flex items-center gap-3">
              <span
                className={cn(
                  "ui-chip ui-chip-sm ui-chip-pill font-bold",
                  badgeBgMap[meta.color],
                )}
              >
                {meta.label}
              </span>
              <h3 className="font-mono text-sm font-medium text-foreground">
                Configure Model
              </h3>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-surface-hover hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Body */}
          <div className="space-y-5 px-5 py-5">
            {/* Model Selector */}
            <div className="space-y-2">
              <label className="flex items-center gap-2 ui-label">
                <HardDrive className="h-3 w-3" />
                Model
              </label>

              {loadingModels ? (
                <div className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2.5 text-sm text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Loading Ollama models...
                </div>
              ) : ollamaError ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 font-mono text-[11px] text-warning">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    {ollamaError}
                  </div>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Enter model name manually"
                    className="w-full rounded-md border border-border bg-card px-3 py-2 font-mono text-sm text-foreground outline-none transition-colors placeholder:text-muted-foreground/50 focus:border-primary"
                  />
                </div>
              ) : (
                <div className="space-y-2">
                  <select
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full cursor-pointer rounded-md border border-border bg-card px-3 py-2.5 font-mono text-sm text-foreground outline-none transition-colors focus:border-primary"
                  >
                    {/* Keep current value as option even if not in the list */}
                    {!available.some((m) => m.name === name) && (
                      <option value={name}>{name} (current)</option>
                    )}
                    {available.map((m) => (
                      <option key={m.name} value={m.name}>
                        {m.name}
                        {m.parameter_size ? ` — ${m.parameter_size}` : ""}
                        {m.size ? ` (${m.size})` : ""}
                      </option>
                    ))}
                  </select>
                  <div className="ui-meta text-muted-foreground/60">
                    {available.length} model{available.length !== 1 ? "s" : ""} available on Ollama
                  </div>
                </div>
              )}
            </div>

            {/* Temperature Slider */}
            <div className="space-y-2">
              <label className="flex items-center justify-between">
                <span className="ui-label">
                  Temperature
                </span>
                <span className="font-mono text-xs tabular-nums text-foreground">
                  {temperature.toFixed(2)}
                </span>
              </label>
              <input
                type="range"
                min="0"
                max="2"
                step="0.05"
                value={temperature}
                onChange={(e) => setTemperature(parseFloat(e.target.value))}
                className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-border outline-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-primary [&::-webkit-slider-thumb]:shadow-md [&::-webkit-slider-thumb]:transition-transform [&::-webkit-slider-thumb]:hover:scale-125"
              />
              <div className="flex justify-between ui-meta ui-meta-xs text-muted-foreground/50">
                <span>Precise</span>
                <span>Creative</span>
              </div>
            </div>

            {/* Max Tokens */}
            <div className="space-y-2">
              <label className="flex items-center justify-between">
                <span className="ui-label">
                  Max Tokens
                </span>
                <span className="font-mono text-xs tabular-nums text-foreground">
                  {maxTokens.toLocaleString()}
                </span>
              </label>
              <input
                type="range"
                min="128"
                max="16384"
                step="128"
                value={maxTokens}
                onChange={(e) => setMaxTokens(parseInt(e.target.value))}
                className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-border outline-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-primary [&::-webkit-slider-thumb]:shadow-md [&::-webkit-slider-thumb]:transition-transform [&::-webkit-slider-thumb]:hover:scale-125"
              />
              <div className="flex justify-between ui-meta ui-meta-xs text-muted-foreground/50">
                <span>128</span>
                <span>16,384</span>
              </div>
            </div>

            {/* Save Error */}
            {saveError && (
              <div className="flex items-center gap-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 font-mono text-[11px] text-danger">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                {saveError}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 border-t border-border px-5 py-4">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border border-border bg-card px-4 py-2 ui-label text-muted-foreground transition-colors hover:bg-surface-hover hover:text-foreground"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={!hasChanges || saving || saved}
              className={cn(
                "inline-flex items-center gap-2 rounded-md px-4 py-2 ui-label transition-all",
                hasChanges && !saving && !saved
                  ? "bg-primary text-primary-foreground hover:opacity-90 glow-cyan"
                  : "cursor-not-allowed bg-muted text-muted-foreground",
              )}
            >
              {saved ? (
                <>
                  <Check className="h-3.5 w-3.5" />
                  Saved
                </>
              ) : saving ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="h-3.5 w-3.5" />
                  Save Changes
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
