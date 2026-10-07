'use client';

import { useState } from 'react';
import {
  DISCLAIMER_INTRO,
  DISCLAIMER_OBLIGATIONS,
  DISCLAIMER_LAWS,
} from '@/lib/disclaimer-copy';

interface DisclaimerModalProps {
  open: boolean;
  target: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function DisclaimerModal({ open, target, onConfirm, onCancel }: DisclaimerModalProps) {
  const [typed, setTyped] = useState('');
  const canConfirm = typed.trim().toLowerCase() === target.trim().toLowerCase();

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-zimlama-negro/90 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="disclaimer-title"
    >
      <div className="zimlama-card max-w-2xl w-full my-8 max-h-[90vh] overflow-y-auto">
        <h2 id="disclaimer-title" className="text-2xl font-titulos font-bold text-sev-alto mb-3">
          ⚠ PENTESTER RESPONSIBILITY
        </h2>

        <p className="text-sm text-zimlama-blanco/90 mb-3">{DISCLAIMER_INTRO}</p>
        <ol className="list-decimal pl-5 space-y-1 text-sm text-zimlama-blanco/80 mb-4">
          {DISCLAIMER_OBLIGATIONS.map((o, i) => (
            <li key={i}>{o}</li>
          ))}
        </ol>

        <details className="mb-4">
          <summary className="cursor-pointer text-sm font-titulos font-bold text-zimlama-piel">
            Applicable laws (LATAM + Global)
          </summary>
          <div className="mt-2 space-y-3 text-xs text-zimlama-blanco/70 max-h-48 overflow-y-auto">
            {DISCLAIMER_LAWS.map((r) => (
              <div key={r.region}>
                <p className="font-titulos font-bold text-zimlama-blanco/90 mb-1">{r.region}</p>
                <ul className="list-disc pl-4 space-y-1">
                  {r.laws.map((l, i) => (
                    <li key={i}>
                      <strong>{l.name}</strong> — {l.summary}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </details>

        <div className="bg-zimlama-negro/50 border border-sev-alto/30 rounded p-3 mb-4">
          <p className="text-xs text-zimlama-gris uppercase tracking-wide mb-1">Target</p>
          <p className="font-mono text-zimlama-blanco">{target}</p>
        </div>

        <p className="text-sm text-zimlama-blanco/80 mb-2">
          Type the target domain to confirm: <code className="font-mono">{target}</code>
        </p>
        <input
          type="text"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          className="zimlama-input mb-4"
          placeholder={target}
          aria-label="Type target to confirm"
          autoComplete="off"
          autoCorrect="off"
          spellCheck={false}
        />

        <div className="flex gap-3 justify-end">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm text-zimlama-blanco/80 hover:text-zimlama-blanco border border-zimlama-gris/50 rounded"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={!canConfirm}
            className="zimlama-button"
          >
            Confirm + Run
          </button>
        </div>
      </div>
    </div>
  );
}
