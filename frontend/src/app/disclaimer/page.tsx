import { FULL_DISCLAIMER_TEXT } from '@/lib/disclaimer-copy';

export default function DisclaimerPage() {
  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-titulos font-bold text-zimlama-blanco mb-2">
          Pentester Responsibility & Legal Disclaimer
        </h1>
        <p className="text-zimlama-gris">
          Read carefully before using zimlama/recon. By proceeding, you accept ALL of the
          following.
        </p>
      </div>

      <pre className="text-sm text-zimlama-blanco/90 whitespace-pre-wrap font-cuerpo bg-zimlama-negro/40 p-6 rounded-lg border border-zimlama-gris/30">
        {FULL_DISCLAIMER_TEXT}
      </pre>
    </div>
  );
}
