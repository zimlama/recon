'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { listJobs, type Job } from '@/lib/api-client';
import { formatDate, formatDuration } from '@/lib/utils';

const statusVariants: Record<string, 'default' | 'success' | 'warning' | 'danger' | 'info'> = {
  pending: 'neutral',
  running: 'info',
  validating: 'info',
  completed: 'success',
  failed: 'danger',
  cancelled: 'warning',
};

export function JobList() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listJobs()
      .then((data) => {
        setJobs(data.items);
        setLoading(false);
      })
      .catch((e) => {
        setError((e as Error).message);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Jobs</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-8 w-full mb-2" />
          <Skeleton className="h-8 w-full mb-2" />
          <Skeleton className="h-8 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Jobs</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sev-critico">Error: {error}</p>
        </CardContent>
      </Card>
    );
  }

  if (jobs.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Jobs</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-zimlama-gris">
            No jobs yet.{' '}
            <Link href="/jobs/new" className="text-zimlama-rojo">
              Create the first one
            </Link>
            .
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Jobs ({jobs.length})</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <THead>
            <TR>
              <TH>Target</TH>
              <TH>Status</TH>
              <TH>Created</TH>
              <TH>Duration</TH>
              <TH>Modules</TH>
              <TH></TH>
            </TR>
          </THead>
          <TBody>
            {jobs.map((job) => (
              <TR key={job.id}>
                <TD>
                  <Link
                    href={`/jobs/${job.id}`}
                    className="font-mono text-zimlama-blanco hover:text-zimlama-rojo no-underline"
                  >
                    {job.target}
                  </Link>
                </TD>
                <TD>
                  <Badge variant={statusVariants[job.status] ?? 'default'}>
                    {job.status}
                  </Badge>
                </TD>
                <TD className="text-zimlama-gris text-xs">
                  {formatDate(job.created_at)}
                </TD>
                <TD className="text-zimlama-gris text-xs font-mono">
                  {formatDuration(job.duration_seconds)}
                </TD>
                <TD className="text-zimlama-gris text-xs">
                  {job.selected_modules.length} modules
                </TD>
                <TD>
                  <Link
                    href={`/jobs/${job.id}`}
                    className="text-zimlama-rojo text-sm no-underline"
                  >
                    View →
                  </Link>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </CardContent>
    </Card>
  );
}
