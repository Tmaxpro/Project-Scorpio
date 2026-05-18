import { useState } from "react";
import { Eye, EyeOff, KeyRound, Lock, ShieldOff, Ticket } from "lucide-react";
import type { AuthType } from "@/lib/types";
import { cn } from "@/lib/utils";

export interface AuthConfigValue {
  type: AuthType;
  bearerToken?: string;
  apiKeyName?: string;
  apiKeyValue?: string;
  apiKeyIn?: "header" | "query";
  basicUser?: string;
  basicPass?: string;
}

interface AuthConfigProps {
  value: AuthConfigValue;
  onChange: (value: AuthConfigValue) => void;
}

const OPTIONS: {
  type: AuthType;
  label: string;
  icon: typeof Lock;
  desc: string;
}[] = [
    { type: "bearer", label: "Bearer Token", icon: Lock, desc: "JWT or OAuth access token" },
    { type: "apikey", label: "API Key", icon: KeyRound, desc: "Header or query param key" },
    { type: "basic", label: "Basic Auth", icon: Ticket, desc: "Username + password" },
    { type: "none", label: "No Auth", icon: ShieldOff, desc: "Public, unauthenticated API" },
  ];

const inputCls =
  "w-full rounded-md border border-border bg-card px-3 py-2 text-sm text-foreground outline-none transition-colors placeholder:text-muted-foreground/50 focus:border-primary";

export function AuthConfig({ value, onChange }: AuthConfigProps) {
  const [showSecret, setShowSecret] = useState(false);

  const update = (patch: Partial<AuthConfigValue>) => onChange({ ...value, ...patch });

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {OPTIONS.map(({ type, label, icon: Icon, desc }) => {
          const active = value.type === type;
          return (
            <button
              key={type}
              type="button"
              onClick={() => update({ type })}
              className={cn(
                "group flex flex-col items-start gap-2 rounded-md border p-4 text-left transition-all",
                active
                  ? "border-primary bg-primary/5 glow-cyan"
                  : "border-border bg-card hover:border-primary/40 hover:bg-surface-hover",
              )}
            >
              <Icon
                className={cn(
                  "h-5 w-5",
                  active ? "text-primary" : "text-muted-foreground",
                )}
              />
              <div>
                <div
                  className={cn(
                    "font-mono text-xs uppercase tracking-wider",
                    active ? "text-primary" : "text-foreground",
                  )}
                >
                  {label}
                </div>
                <div className="mt-1 text-[11px] text-muted-foreground">{desc}</div>
              </div>
            </button>
          );
        })}
      </div>

      <div className="ui-panel-muted">
        {value.type === "bearer" && (
          <div className="space-y-2">
            <label className="ui-label">
              Token
            </label>
            <div className="relative">
              <input
                type={showSecret ? "text" : "password"}
                value={value.bearerToken ?? ""}
                onChange={(e) => update({ bearerToken: e.target.value })}
                placeholder="eyJhbGciOi..."
                className={cn(inputCls, "pr-10 font-mono")}
              />
              <button
                type="button"
                onClick={() => setShowSecret((v) => !v)}
                aria-label={showSecret ? "Hide token" : "Show token"}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
        )}

        {value.type === "apikey" && (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <div className="space-y-2">
              <label className="ui-label">
                Key Name
              </label>
              <input
                value={value.apiKeyName ?? ""}
                onChange={(e) => update({ apiKeyName: e.target.value })}
                placeholder="X-API-Key"
                className={cn(inputCls, "font-mono")}
              />
            </div>
            <div className="space-y-2">
              <label className="ui-label">
                Key Value
              </label>
              <input
                type={showSecret ? "text" : "password"}
                value={value.apiKeyValue ?? ""}
                onChange={(e) => update({ apiKeyValue: e.target.value })}
                placeholder="sk_live_..."
                className={cn(inputCls, "font-mono")}
              />
            </div>
            <div className="space-y-2">
              <label className="ui-label">
                Placement
              </label>
              <select
                value={value.apiKeyIn ?? "header"}
                onChange={(e) =>
                  update({ apiKeyIn: e.target.value as "header" | "query" })
                }
                className={inputCls}
              >
                <option value="header">Header</option>
                <option value="query">Query Parameter</option>
              </select>
            </div>
          </div>
        )}

        {value.type === "basic" && (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-2">
              <label className="ui-label">
                Username
              </label>
              <input
                value={value.basicUser ?? ""}
                onChange={(e) => update({ basicUser: e.target.value })}
                placeholder="admin"
                className={inputCls}
              />
            </div>
            <div className="space-y-2">
              <label className="ui-label">
                Password
              </label>
              <input
                type={showSecret ? "text" : "password"}
                value={value.basicPass ?? ""}
                onChange={(e) => update({ basicPass: e.target.value })}
                placeholder="••••••••"
                className={inputCls}
              />
            </div>
          </div>
        )}

        {value.type === "none" && (
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <ShieldOff className="h-4 w-4" />
            No credentials will be attached. Scan will probe public endpoints only.
          </div>
        )}
      </div>
    </div>
  );
}
