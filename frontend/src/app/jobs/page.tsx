import { JobList } from '@/components/JobList';

export default function JobsPage() {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-titulos font-bold text-zimlama-blanco">Jobs</h1>
        <a
          href="/jobs/new"
          className="bg-zimlama-rojo text-zimlama-blanco px-4 py-2 rounded-md font-titulos font-bold no-underline hover:opacity-90"
        >
          + New Job
        </a>
      </div>
      <JobList />
    </div>
  );
}
