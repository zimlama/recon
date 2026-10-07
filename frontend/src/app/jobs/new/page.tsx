import { JobCreatorForm } from '@/components/JobCreatorForm';

export default function NewJobPage() {
  return (
    <div className="max-w-2xl mx-auto space-y-4">
      <h1 className="text-3xl font-titulos font-bold text-zimlama-blanco">
        New Recon Job
      </h1>
      <p className="text-zimlama-gris">
        Configure your recon target and select the modules to run. You will be asked
        to accept the pentester responsibility disclaimer before the job starts.
      </p>
      <JobCreatorForm />
    </div>
  );
}
