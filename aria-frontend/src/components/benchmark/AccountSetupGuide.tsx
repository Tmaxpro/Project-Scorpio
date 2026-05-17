import { useState } from "react";
import { ChevronDown, ChevronUp, CheckCircle2, Circle, Users, Copy } from "lucide-react";
import type { AccountRequirement } from "@/lib/types";
import { cn } from "@/lib/utils";

interface AccountSetupGuideProps {
  accounts: AccountRequirement[];
  /** Currently filled tokens keyed by credentials_field. */
  filled: Record<string, boolean>;
}

export function AccountSetupGuide({ accounts, filled }: AccountSetupGuideProps) {
  const [open, setOpen] = useState(true);
  if (accounts.length === 0) return null;

  return (
    <div className="glass rounded-lg border border-border">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-4 py-3"
      >
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-primary" />
          <span className="font-mono text-xs uppercase tracking-widest text-foreground">
            Account setup required
          </span>
          <span className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground">
            {accounts.length}
          </span>
        </div>
        {open ? (
          <ChevronUp className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        )}
      </button>

      {open && (
        <div className="space-y-4 border-t border-border px-4 py-4">
          {accounts.map((acc) => (
            <AccountBlock
              key={acc.credentials_field}
              account={acc}
              isFilled={!!filled[acc.credentials_field]}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function AccountBlock({
  account,
  isFilled,
}: {
  account: AccountRequirement;
  isFilled: boolean;
}) {
  return (
    <div className="rounded-md border border-border bg-card/40 p-3">
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            {isFilled ? (
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-success" />
            ) : (
              <Circle className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            )}
            <span className="font-mono text-xs text-foreground">{account.label}</span>
            {!account.required && (
              <span className="rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-warning">
                Optional
              </span>
            )}
          </div>
          <p className="ml-5 mt-0.5 text-[11px] text-muted-foreground">
            {account.purpose}
          </p>
        </div>
      </div>

      {/* Setup steps */}
      <ol className="ml-5 mb-3 space-y-1">
        {account.setup_steps.map((step, i) => (
          <li
            key={i}
            className="flex items-start gap-2 font-mono text-[10px] text-muted-foreground"
          >
            <span className="shrink-0 text-primary">{i + 1}.</span>
            <CopyableStep text={step} />
          </li>
        ))}
      </ol>

      {/* Required-for chips */}
      {account.required_for && account.required_for.length > 0 && (
        <div className="ml-5 flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
            Required for:
          </span>
          {account.required_for.map((id) => (
            <span
              key={id}
              className={cn(
                "rounded border px-1.5 py-0.5 font-mono text-[9px]",
                isFilled
                  ? "border-success/40 bg-success/10 text-success"
                  : "border-warning/40 bg-warning/10 text-warning",
              )}
            >
              {id}
            </span>
          ))}
        </div>
      )}

      {/* Skip warning if optional + not filled */}
      {!account.required && !isFilled && account.required_for && (
        <p className="ml-5 mt-2 font-mono text-[10px] italic text-warning">
          Without this token, {account.required_for.length} ground truth{" "}
          {account.required_for.length === 1 ? "entry" : "entries"} will be untestable.
        </p>
      )}
    </div>
  );
}

function CopyableStep({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const looksLikeCode = /^(POST|GET|PUT|DELETE|PATCH|Body:|Note)/i.test(text);

  if (!looksLikeCode) {
    return <span>{text}</span>;
  }

  const copy = () => {
    void navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      onClick={copy}
      title={copied ? "Copied!" : "Click to copy"}
      className="group flex w-full items-center gap-2 text-left font-mono text-[10px] text-foreground hover:text-primary"
    >
      <span className="flex-1 whitespace-pre-wrap break-all">{text}</span>
      {copied ? (
        <CheckCircle2 className="h-3 w-3 shrink-0 text-success" />
      ) : (
        <Copy className="h-3 w-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
      )}
    </button>
  );
}
