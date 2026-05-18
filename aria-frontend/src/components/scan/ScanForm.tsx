import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { z } from "zod";
import { ArrowLeft, ArrowRight, Check, Loader2, Zap } from "lucide-react";
import { YamlEditor } from "./YamlEditor";
import { AuthConfig, type AuthConfigValue } from "./AuthConfig";
import { OWASPSelector } from "./OWASPSelector";
import { createScan } from "@/lib/api";
import type { OWASPCategory, ScanRequest } from "@/lib/types";
import { OWASP_META } from "@/lib/types";
import { cn } from "@/lib/utils";

const STEPS = [
  { id: 1, name: "Target" },
  { id: 2, name: "OpenAPI Spec" },
  { id: 3, name: "Authentication" },
  { id: 4, name: "Options" },
] as const;

const targetSchema = z.object({
  baseUrl: z
    .string()
    .trim()
    .min(1, "Required")
    .url("Must be a valid URL")
    .refine(
      (v) => v.startsWith("http://") || v.startsWith("https://"),
      "Must start with http:// or https://",
    ),
  scanName: z.string().trim().max(120).optional(),
});

export function ScanForm() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [baseUrl, setBaseUrl] = useState("");
  const [scanName, setScanName] = useState("");
  const [targetErrors, setTargetErrors] = useState<{ baseUrl?: string; scanName?: string }>({});

  const [yamlText, setYamlText] = useState("");
  const [yamlValid, setYamlValid] = useState(false);

  const [auth, setAuth] = useState<AuthConfigValue>({ type: "none", apiKeyIn: "header" });
  const [categories, setCategories] = useState<OWASPCategory[]>(
    Object.keys(OWASP_META) as OWASPCategory[],
  );
  const [context, setContext] = useState("");

  const validateTarget = () => {
    const r = targetSchema.safeParse({ baseUrl, scanName });
    if (!r.success) {
      const errs: { baseUrl?: string; scanName?: string } = {};
      for (const issue of r.error.issues) {
        const k = issue.path[0] as "baseUrl" | "scanName";
        errs[k] = issue.message;
      }
      setTargetErrors(errs);
      return false;
    }
    setTargetErrors({});
    return true;
  };

  const validateAuth = (): boolean => {
    if (auth.type === "bearer") return !!auth.bearerToken?.trim();
    if (auth.type === "apikey")
      return !!auth.apiKeyName?.trim() && !!auth.apiKeyValue?.trim();
    if (auth.type === "basic") return !!auth.basicUser?.trim() && !!auth.basicPass?.trim();
    return true;
  };

  const canAdvance = () => {
    if (step === 1) return targetSchema.safeParse({ baseUrl, scanName }).success;
    if (step === 2) return yamlValid;
    if (step === 3) return validateAuth();
    if (step === 4) return categories.length > 0;
    return false;
  };

  const next = () => {
    if (step === 1 && !validateTarget()) return;
    if (!canAdvance()) return;
    setStep((s) => Math.min(4, s + 1));
  };
  const back = () => setStep((s) => Math.max(1, s - 1));

  const buildCredentials = (): Record<string, string> | undefined => {
    if (auth.type === "bearer") return { token: auth.bearerToken ?? "" };
    if (auth.type === "apikey")
      return {
        name: auth.apiKeyName ?? "",
        value: auth.apiKeyValue ?? "",
        in: auth.apiKeyIn ?? "header",
      };
    if (auth.type === "basic")
      return { username: auth.basicUser ?? "", password: auth.basicPass ?? "" };
    return undefined;
  };

  const submit = async () => {
    if (!canAdvance()) return;
    setSubmitting(true);
    setSubmitError(null);
    const payload: ScanRequest = {
      openapi_yaml: yamlText,
      base_url: baseUrl.trim(),
      scan_name: scanName.trim() || undefined,
      auth_type: auth.type,
      credentials: buildCredentials(),
      context: context.trim() || undefined,
      owasp_categories: categories,
    };
    try {
      const { scan_id } = await createScan(payload);
      navigate({ to: "/scan/$id", params: { id: scan_id } });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to launch scan";
      setSubmitError(msg);
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      <Stepper current={step} />

      <div className="glass min-h-[400px] rounded-lg p-6">
        {step === 1 && (
          <StepBlock title="Target" caption="Where should ARIA point its agents?">
            <div className="grid grid-cols-1 gap-4">
              <Field
                label="Target Base URL"
                error={targetErrors.baseUrl}
                required
              >
                <input
                  type="url"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  onBlur={validateTarget}
                  placeholder="https://api.example.com"
                  className={inputCls(!!targetErrors.baseUrl)}
                />
              </Field>
              <Field label="Scan Name" hint="Optional — for history display">
                <input
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  placeholder="Q4 production audit"
                  className={inputCls(false)}
                />
              </Field>
            </div>
          </StepBlock>
        )}

        {step === 2 && (
          <StepBlock title="OpenAPI Specification" caption="Paste or upload your API spec">
            <YamlEditor
              value={yamlText}
              onChange={setYamlText}
              onValidityChange={setYamlValid}
            />
          </StepBlock>
        )}

        {step === 3 && (
          <StepBlock title="Authentication" caption="How will ARIA authenticate to the target?">
            <AuthConfig value={auth} onChange={setAuth} />
          </StepBlock>
        )}

        {step === 4 && (
          <StepBlock title="Scan Options" caption="Pick OWASP categories and add context">
            <div className="space-y-6">
              <OWASPSelector selected={categories} onChange={setCategories} />
              <Field
                label="Additional Context"
                hint="Hints that help agents reason about the API"
              >
                <textarea
                  value={context}
                  onChange={(e) => setContext(e.target.value)}
                  rows={4}
                  maxLength={1000}
                  placeholder="Admin endpoints use /admin/ prefix. JWT tokens expire in 1h."
                  className={cn(inputCls(false), "resize-none font-mono text-xs")}
                />
              </Field>
            </div>
          </StepBlock>
        )}

        {submitError && (
          <div className="mt-4 rounded-md border border-danger/40 bg-danger/10 p-3 font-mono text-xs text-danger">
            {submitError}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={back}
          disabled={step === 1 || submitting}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-4 py-2 text-sm text-foreground transition-colors hover:bg-surface-hover disabled:opacity-40"
        >
          <ArrowLeft className="h-4 w-4" />
          Back
        </button>

        {step < 4 ? (
          <button
            type="button"
            onClick={next}
            disabled={!canAdvance()}
            className={cn(
              "inline-flex items-center gap-2 rounded-md px-4 py-2 font-mono text-xs uppercase tracking-widest transition-all",
              canAdvance()
                ? "bg-primary text-primary-foreground hover:glow-cyan"
                : "cursor-not-allowed bg-muted text-muted-foreground",
            )}
          >
            Continue
            <ArrowRight className="h-4 w-4" />
          </button>
        ) : (
          <button
            type="button"
            onClick={submit}
            disabled={!canAdvance() || submitting}
            className={cn(
              "inline-flex items-center gap-2 rounded-md px-5 py-2.5 font-mono text-xs font-bold uppercase tracking-widest transition-all",
              !canAdvance() || submitting
                ? "cursor-not-allowed bg-muted text-muted-foreground"
                : "bg-primary text-primary-foreground glow-cyan hover:opacity-90",
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
                Launch Scan
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}

function Stepper({ current }: { current: number }) {
  return (
    <ol className="flex items-center gap-2">
      {STEPS.map((s, idx) => {
        const done = current > s.id;
        const active = current === s.id;
        return (
          <li key={s.id} className="flex flex-1 items-center gap-2">
            <div
              className={cn(
                "flex h-8 w-8 shrink-0 items-center justify-center rounded-full border font-mono text-xs transition-all",
                done && "border-success bg-success/20 text-success",
                active && "border-primary bg-primary/20 text-primary glow-cyan",
                !done && !active && "border-border bg-card text-muted-foreground",
              )}
            >
              {done ? <Check className="h-4 w-4" /> : s.id}
            </div>
            <div className="hidden min-w-0 flex-1 sm:block">
              <div
                className={cn(
                  "truncate font-mono text-[10px] uppercase tracking-widest",
                  active
                    ? "text-primary"
                    : done
                      ? "text-success"
                      : "text-muted-foreground",
                )}
              >
                {s.name}
              </div>
            </div>
            {idx < STEPS.length - 1 && (
              <div
                className={cn(
                  "h-px flex-1 transition-colors",
                  done ? "bg-success/60" : "bg-border",
                )}
              />
            )}
          </li>
        );
      })}
    </ol>
  );
}

function StepBlock({
  title,
  caption,
  children,
}: {
  title: string;
  caption: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-5">
      <div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-primary">
          Step
        </div>
        <h2 className="mt-1 text-xl font-semibold text-foreground">{title}</h2>
        <p className="text-sm text-muted-foreground">{caption}</p>
      </div>
      {children}
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
