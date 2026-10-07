'use client';

import { useState, useEffect, use } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import {
  getJob,
  getHandoff,
  cancelJob,
  deleteJob,
  generateReport,
  type Job,
  type HandoffPacket,
} from '@/lib/api-client';
import { ModuleCard } from '@/components/ModuleCard';
import { formatDate, formatDuration } from '@/lib/utils';

export default function JobDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [job, setJob] = useState<Job | null>(null);
  const [handoff, setHandoff] = useState<HandoffPacket | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    loadJob();
  }, [id]);

  async function loadJob() {
    setLoading(true);
    try {
      const data = await getJob(id);
      setJob(data);
      // Try to load handoff (will succeed if job completed)
      try {
        const h = await getHandoff(id);
        setHandoff(h as HandoffPacket);
      } catch {
        // handoff not available yet, that's OK
      }
      setLoading(false);
    } catch (e) {
      setError((e as Error).message);
      setLoading(false);
    }
  }

  async function handleCancel() {
    if (!confirm('Cancel this job?')) return;
    try {
      await cancelJob(id);
      await loadJob();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function handleDelete() {
    if (!confirm('Delete this job and ALL its data? This cannot be undone.')) return;
    try {
      await deleteJob(id);
      window.location.href = '/jobs';
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function handleGenerateReport() {
    setGenerating(true);
    try {
      await generateReport(id);
      await loadJob();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setGenerating(false);
    }
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-12 w-1/2" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (error || !job) {
    return (
      <Card>
        <CardContent>
          <p className="text-sev-critico">Error: {error ?? 'Job not found'}</p>
        </CardContent>
      </Card>
    );
  }

  const statusVariant: 'default' | 'success' | 'warning' | 'danger' | 'info' =
    job.status === 'completed' ? 'success' :
    job.status === 'failed' ? 'danger' :
    job.status === 'cancelled' ? 'warning' :
    'info';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="font-mono text-2xl text-zimlama-blanco">{job.target}</h1>
            <Badge variant={statusVariant}>{job.status}</Badge>
          </div>
          <p className="text-sm text-zimlama-gris">
            Job ID: <span className="font-mono">{job.id}</span>
          </p>
          <p className="text-xs text-zimlama-gris mt-1">
            Created: {formatDate(job.created_at)} · Duration:{' '}
            {formatDuration(job.duration_seconds)}
          </p>
        </div>
        <div className="flex gap-2">
          {(job.status === 'pending' || job.status === 'running') && (
            <Button variant="secondary" size="sm" onClick={handleCancel}>
              Cancel
            </Button>
          )}
          <Button variant="danger" size="sm" onClick={handleDelete}>
            Delete
          </Button>
        </div>
      </div>

      {/* Reports */}
      <Card>
        <CardHeader>
          <CardTitle>Reports</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3 items-center">
            {job.report_pdf_path ? (
              <>
                <a
                  href={`/api/v1/jobs/${job.id}/report/download?format=pdf`}
                  className="text-zimlama-rojo no-underline"
                >
                  📄 Download PDF
                </a>
                <a
                  href={`/api/v1/jobs/${job.id}/report/download?format=md`}
                  className="text-zimlama-rojo no-underline"
                >
                  📝 Download Markdown
                </a>
              </>
            ) : (
              <Button
                onClick={handleGenerateReport}
                disabled={generating || job.status !== 'completed'}
              >
                {generating ? 'Generating...' : 'Generate Report'}
              </Button>
            )}
            {job.status !== 'completed' && !job.report_pdf_path && (
              <span className="text-xs text-zimlama-gris">
                Report available when job completes
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Handoff */}
      {handoff && (
        <Card>
          <CardHeader>
            <CardTitle>Handoff Packet (v{handoff.schema_version})</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-zimlama-gris mb-3">
              Vendor-neutral JSON document that a future Phase 2 (scanning) tool can consume.
            </p>
            <div className="flex gap-3">
              <Link
                href={`/handoff/${job.id}`}
                className="text-zimlama-rojo no-underline"
              >
                View Handoff →
              </Link>
              <a
                href={`/api/v1/jobs/${job.id}/handoff/download`}
                className="text-zimlama-rojo no-underline"
              >
                Download JSON
              </a>
            </div>
            <div className="mt-3 text-xs text-zimlama-gris">
              Source: <span className="font-mono">{handoff.source.repo}</span> v
              <span className="font-mono">{handoff.source.version}</span> ·{' '}
              {handoff.confirmed_targets.length} confirmed targets
            </div>
          </CardContent>
        </Card>
      )}

      {/* Module Runs */}
      <div>
        <h2 className="font-titulos font-bold text-xl text-zimlama-blanco mb-3">
          Modules ({job.module_runs?.length ?? 0})
        </h2>
        {job.module_runs && job.module_runs.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {job.module_runs.map((mr) => (
              <ModuleCard key={mr.id} moduleRun={mr} />
            ))}
          </div>
        ) : (
          <p className="text-zimlama-gris">No modules have run yet.</p>
        )}
      </div>

      {/* Selected modules (raw) */}
      {job.selected_modules && job.selected_modules.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Selected Modules</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {job.selected_modules.map((m) => (
                <span
                  key={m}
                  className="font-mono text-xs px-2 py-1 bg-zimlama-gris/30 rounded"
                >
                  {m}
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {job.error_message && (
        <Card>
          <CardContent>
            <p className="text-sev-critico">Error: {job.error_message}</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
