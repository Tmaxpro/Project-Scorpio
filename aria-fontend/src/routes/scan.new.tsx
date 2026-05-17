import { createFileRoute } from "@tanstack/react-router";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { ScanForm } from "@/components/scan/ScanForm";

export const Route = createFileRoute("/scan/new")({
  head: () => ({
    meta: [
      { title: "New Scan — ARIA" },
      {
        name: "description",
        content: "Configure a new autonomous API security scan with ARIA.",
      },
    ],
  }),
  component: NewScanPage,
});

function NewScanPage() {
  return (
    <>
      <TopBar
        title="New Scan"
        subtitle="Configure target, spec, auth, and OWASP coverage"
      />
      <PageContainer className="max-w-5xl">
        <ScanForm />
      </PageContainer>
    </>
  );
}
