'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { JobList } from '@/components/JobList';
import { Skeleton } from '@/components/ui/skeleton';
import { listJobs } from '@/lib/api-client';
import { listModules } from '@/lib/api-client';

export default function DashboardPage() {
  const [jobCount, setJobCount] = useState<number | null>(null);
  const [moduleCount, setModuleCount] = useState<number | null>(null);

  useEffect(() => {
    listJobs().then((d) => setJobCount(d.items.length)).catch(() => {});
    listModules().then((d) => setModuleCount(d.total)).catch(() => {});
  }, []);

  return (
    <div className="space-y-8">
      {/* Hero */}
      <section className="text-center py-8">
        <h1 className="text-4xl font-titulos font-bold mb-2 text-zimlama-blanco">
          zimlama recon
        </h1>
        <p className="text-lg text-zimlama-gris mb-1">
          Phase 1 ethical hacking reconnaissance
        </p>
        <p className="text-sm text-zimlama-gris/70 mb-6">
          Self-hosted · Open source · AI-validated · Vendor-neutral
        </p>
        <a
          href="/jobs/new"
          className="inline-block bg-zimlama-rojo text-zimlama-blanco px-6 py-3 rounded-md font-titulos font-bold no-underline hover:opacity-90"
        >
          Start a new recon →
        </a>
      </section>

      {/* Stats */}
      <section className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <p className="text-xs text-zimlama-gris uppercase tracking-wide">Total Jobs</p>
          <p className="text-3xl font-titulos font-bold text-zimlama-blanco mt-1">
            {jobCount ?? <Skeleton className="h-8 w-12" />}
          </p>
        </Card>
        <Card>
          <p className="text-xs text-zimlama-gris uppercase tracking-wide">
            Modules Available
          </p>
          <p className="text-3xl font-titulos font-bold text-zimlama-blanco mt-1">
            {moduleCount ?? <Skeleton className="h-8 w-12" />}
          </p>
        </Card>
        <Card>
          <p className="text-xs text-zimlama-gris uppercase tracking-wide">AI Provider</p>
          <p className="text-3xl font-titulos font-bold text-zimlama-blanco mt-1">M3</p>
        </Card>
      </section>

      {/* Recent jobs */}
      <section>
        <h2 className="text-xl font-titulos font-bold text-zimlama-blanco mb-3">
          Recent Jobs
        </h2>
        <JobList />
      </section>

      {/* Disclaimer callout */}
      <section className="border border-sev-alto/30 bg-sev-alto/5 rounded-lg p-4">
        <h3 className="font-titulos font-bold text-sev-alto mb-1">⚠ Authorized Use Only</h3>
        <p className="text-sm text-zimlama-blanco/80">
          This tool sends real network requests. Use only on systems you have{' '}
          <strong>WRITTEN AUTHORIZATION</strong> to test. Unauthorized access is a crime under your
          local laws (see the full{' '}
          <a href="/disclaimer" className="text-zimlama-rojo no-underline">
            disclaimer
          </a>
          ).
        </p>
      </section>
    </div>
  );
}
