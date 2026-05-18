import { useMemo, useRef, useState } from "react";
import yaml from "js-yaml";
import { CheckCircle2, FileUp, AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface YamlEditorProps {
  value: string;
  onChange: (value: string) => void;
  onValidityChange?: (valid: boolean) => void;
}

interface ParsedSpec {
  paths?: Record<string, Record<string, unknown>>;
}

export function YamlEditor({ value, onChange, onValidityChange }: YamlEditorProps) {
  const [tab, setTab] = useState<"paste" | "upload">("paste");
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const parseResult = useMemo(() => {
    if (!value.trim()) return { ok: false, error: "", endpoints: 0, empty: true };
    try {
      const parsed = yaml.load(value) as ParsedSpec | null;
      if (!parsed || typeof parsed !== "object") {
        return { ok: false, error: "Document is empty or invalid", endpoints: 0, empty: false };
      }
      let endpoints = 0;
      if (parsed.paths && typeof parsed.paths === "object") {
        for (const methods of Object.values(parsed.paths)) {
          if (methods && typeof methods === "object") {
            endpoints += Object.keys(methods).filter((m) =>
              ["get", "post", "put", "patch", "delete", "head", "options"].includes(
                m.toLowerCase(),
              ),
            ).length;
          }
        }
      }
      return { ok: true, error: "", endpoints, empty: false };
    } catch (e) {
      const err = e as { message?: string; mark?: { line?: number } };
      const line = err.mark?.line != null ? ` (line ${err.mark.line + 1})` : "";
      return { ok: false, error: `${err.message ?? "Parse error"}${line}`, endpoints: 0, empty: false };
    }
  }, [value]);

  // Notify parent of validity
  useMemo(() => {
    onValidityChange?.(parseResult.ok);
  }, [parseResult.ok, onValidityChange]);

  const handleFile = async (file: File) => {
    const text = await file.text();
    onChange(text);
    setTab("paste");
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-1 border-b border-border">
        {(["paste", "upload"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={cn(
              "border-b-2 px-4 py-2 ui-label transition-colors",
              tab === t
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t === "paste" ? "Paste YAML" : "Upload File"}
          </button>
        ))}
        <div className="ml-auto pb-2">
          {!parseResult.empty &&
            (parseResult.ok ? (
              <span className="ui-chip ui-chip-sm border-success/40 bg-success/10 text-success">
                <CheckCircle2 className="h-3 w-3" />
                {parseResult.endpoints} endpoints
              </span>
            ) : (
              <span className="ui-chip ui-chip-sm border-danger/40 bg-danger/10 text-danger">
                <AlertCircle className="h-3 w-3" />
                Invalid
              </span>
            ))}
        </div>
      </div>

      {tab === "paste" ? (
        <div className="relative">
          <textarea
            value={value}
            onChange={(e) => onChange(e.target.value)}
            spellCheck={false}
            rows={20}
            placeholder="openapi: 3.0.0&#10;info:&#10;  title: My API&#10;paths:&#10;  /users:&#10;    get: ..."
            className={cn(
              "w-full rounded-md border bg-card p-4 font-mono text-xs text-foreground outline-none transition-colors",
              "placeholder:text-muted-foreground/50",
              parseResult.empty || parseResult.ok
                ? "border-border focus:border-primary"
                : "border-danger/60 focus:border-danger",
            )}
          />
          {!parseResult.ok && !parseResult.empty && (
            <div className="mt-2 flex items-start gap-2 rounded-md border border-danger/40 bg-danger/10 p-2 ui-meta text-danger">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span className="break-all">{parseResult.error}</span>
            </div>
          )}
        </div>
      ) : (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files[0];
            if (f) handleFile(f);
          }}
          onClick={() => fileRef.current?.click()}
          className={cn(
            "flex cursor-pointer flex-col items-center justify-center gap-3 rounded-md border-2 border-dashed py-16 transition-colors",
            dragOver
              ? "border-primary bg-primary/5"
              : "border-border bg-card/40 hover:border-primary/60 hover:bg-surface-hover",
          )}
        >
          <FileUp className="h-8 w-8 text-muted-foreground" />
          <div className="text-center">
            <div className="ui-label text-foreground">
              Drop OpenAPI spec here
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              .yaml · .yml · .json — or click to browse
            </div>
          </div>
          <input
            ref={fileRef}
            type="file"
            accept=".yaml,.yml,.json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) handleFile(f);
            }}
          />
        </div>
      )}
    </div>
  );
}
