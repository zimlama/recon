import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // zimlama brand tokens
        zimlama: {
          negro: 'var(--zimlama-negro)',
          rojo: 'var(--zimlama-rojo)',
          blanco: 'var(--zimlama-blanco)',
          gris: 'var(--zimlama-gris)',
          piel: 'var(--zimlama-piel)',
          purple: 'var(--zimlama-purple)',
        },
        // Severity colors
        sev: {
          critico: 'var(--sev-critico)',
          alto: 'var(--sev-alto)',
          medio: 'var(--sev-medio)',
          bajo: 'var(--sev-bajo)',
          info: 'var(--sev-info)',
        },
      },
      fontFamily: {
        titulos: ['var(--font-titulos)', 'sans-serif'],
        cuerpo: ['var(--font-cuerpo)', 'sans-serif'],
        mono: ['var(--font-mono)', 'monospace'],
      },
      spacing: {
        's1': '4px',
        's2': '8px',
        's3': '12px',
        's4': '16px',
        's5': '24px',
        's6': '32px',
        's7': '48px',
      },
      borderRadius: {
        'r': '10px',
        'r-sm': '6px',
        'r-md': '8px',
        'r-pill': '999px',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
};

export default config;
