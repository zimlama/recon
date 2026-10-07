'use client';

import { use, useEffect, useState } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { getHandoff, type HandoffPacket } from '@/lib/api-client';
import { formatDate } from '@/lib/utils';

export default function HandoffPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [packet, setPacket] = useState<HandoffPacket | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getHandoff(id)
      .then((data) => {
        setPacket(data as HandoffPacket);
        setLoading(false);
      })
      .catch((e) => {
        setError((e as Error).message);
        setLoading(false);
      });
  }, [id]);

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-12 w-1/2" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error || !packet) {
    return (
      <Card>
        <CardContent>
          <p className="text-sev-critico">
            Error loading handoff: {error ?? 'Not found'}
          </p>
          <p className="text-sm text-zimlama-gris mt-2">
            Handoffs are generated when a job completes. Make sure the job is finished.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <h1 className="font-mono text-2xl text-zimlama-blanco">
            Handoff: {packet.target.primary_domain}
          </h1>
          <span className="text-xs font-mono text-zimlama-piel bg-zimlama-piel/10 px-2 py-0.5 rounded">
            v{packet.schema_version}
          </span>
        </div>
        <p className="text-sm text-zimlama-gris">
          Vendor-neutral contract for future Phase 2 (scanning) tools. See{' '}
          <Link
            href="https://github.com/zimlama/recon/blob/main/docs/HANDOFF.md"
            target="_blank"
            rel="noopener noreferrer"
            className="text-zimlama-rojo no-underline"
          >
            HANDOFF.md
          </Link>{' '}
          for schema.
        </p>
        <div className="mt-3 flex gap-3 text-sm">
          <a
            href={`/api/v1/jobs/${id}/handoff/download`}
            className="text-zimlama-rojo no-underline"
          >
            Download JSON
          </a>
          <Link href={`/jobs/${id}`} className="text-zimlama-rojo no-underline">
            ← Back to job
          </Link>
        </div>
      </div>

      {/* Source */}
      <Card>
        <CardHeader>
          <CardTitle>Source</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TBody>
              <TR>
                <TH>Repo</TH>
                <TD className="font-mono">{packet.source.repo}</TD>
              </TR>
              <TR>
                <TH>Version</TH>
                <TD className="font-mono">{packet.source.version}</TD>
              </TR>
              <TR>
                <TH>Job ID</TH>
                <TD className="font-mono text-xs">{packet.source.job_id}</TD>
              </TR>
              <TR>
                <TH>Phase</TH>
                <TD className="font-mono">{packet.source.phase}</TD>
              </TR>
              <TR>
                <TH>Completed</TH>
                <TD>{formatDate(packet.source.completed_at)}</TD>
              </TR>
            </TBody>
          </Table>
        </CardContent>
      </Card>

      {/* Target */}
      <Card>
        <CardHeader>
          <CardTitle>Target</CardTitle>
        </CardHeader>
        <CardContent>
          <p>
            <span className="text-zimlama-gris">Primary domain:</span>{' '}
            <span className="font-mono text-zimlama-blanco">
              {packet.target.primary_domain}
            </span>
          </p>
          <p className="text-sm mt-1">
            <span className="text-zimlama-gris">Scope:</span>{' '}
            <span className="font-mono text-zimlama-blanco">
              {packet.target.authorization_scope}
            </span>
          </p>
          <p className="text-sm mt-1">
            <span className="text-zimlama-gris">Active scan authorized:</span>{' '}
            <span className="font-mono">
              {String(packet.target.active_scan_authorized)}
            </span>
          </p>
        </CardContent>
      </Card>

      {/* Confirmed targets */}
      {packet.confirmed_targets.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Confirmed Targets ({packet.confirmed_targets.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <THead>
                <TR>
                  <TH>Subdomain</TH>
                  <TH>Priority</TH>
                  <TH>Verdict</TH>
                  <TH>Confidence</TH>
                </TR>
              </THead>
              <TBody>
                {packet.confirmed_targets.map((t, i) => (
                  <TR key={i}>
                    <TD className="font-mono">{t.subdomain}</TD>
                    <TD>{t.priority_for_next_phase}</TD>
                    <TD className="text-xs">{t.ai_verdict}</TD>
                    <TD>{(t.ai_confidence * 100).toFixed(0)}%</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Tech stack */}
      <Card>
        <CardHeader>
          <CardTitle>Tech Stack Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="text-xs font-mono bg-zimlama-negro/60 p-3 rounded overflow-x-auto">
            {JSON.stringify(packet.tech_stack_summary, null, 2)}
          </pre>
        </CardContent>
      </Card>

      {/* Recommended modules */}
      {packet.recommended_modules && packet.recommended_modules.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recommended Modules for Phase 2</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {packet.recommended_modules.map((m, i) => (
                <li key={i} className="text-sm">
                  <span className="font-mono text-zimlama-piel">{m.module}</span>{' '}
                  <span className="text-zimlama-gris">({m.priority})</span> —{' '}
                  {m.rationale}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Do-not-scan list */}
      <Card>
        <CardHeader>
          <CardTitle>Do-Not-Scan Ranges ({packet.do_not_scan.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-zimlama-gris mb-2">
            These IP ranges are always excluded (RFC 1918 + reserved). Phase 2 consumers MUST
            honor this list.
          </p>
          <div className="flex flex-wrap gap-2">
            {packet.do_not_scan.map((r) => (
              <code
                key={r}
                className="text-xs font-mono px-2 py-1 bg-zimlama-gris/30 rounded"
              >
                {r}
              </code>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Raw JSON */}
      <Card>
        <CardHeader>
          <CardTitle>Raw JSON</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="text-xs font-mono bg-zimlama-negro/60 p-3 rounded overflow-x-auto max-h-96">
            {JSON.stringify(packet, null, 2)}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
