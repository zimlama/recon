/**
 * LATAM-aware disclaimer copy. Centralized so backend + frontend + report
 * template all use the same language.
 *
 * Covers: Colombia (Art. 269 + Ley 1273/2009), Brasil (Art. 154-A), México
 * (Art. 269), Argentina (Art. 153-157 bis), Chile (Ley 19.223), Perú
 * (Art. 186-A), US (CFAA), EU (Directive 2013/40/EU).
 */

export const DISCLAIMER_INTRO = `By using this tool you confirm ALL of the following:`;

export const DISCLAIMER_OBLIGATIONS = [
  'You have WRITTEN AUTHORIZATION to test the target.',
  'You understand this tool sends real requests to third-party systems, including active scans (when Tier 3 modules are enabled).',
  'You accept full responsibility for any consequences, legal or otherwise, of running this tool.',
  'You will not use this tool against systems you do not own or have explicit permission to test.',
  'You understand that unauthorized access to computer systems is a crime under your local laws.',
];

export const DISCLAIMER_LAWS = [
  {
    region: 'Colombia',
    laws: [
      {
        name: 'Código Penal, Art. 269',
        summary:
          'Acceso abusivo a sistemas informáticos. Pena de prisión de 1 a 4 años, multa de 5 a 100 SMLMV.',
      },
      {
        name: 'Ley 1273 de 2009',
        summary:
          'Delitos informáticos. Adds Art. 269A-E: obstaculización, interceptación, uso de software malicioso, hurto, transferencia no consentida.',
      },
    ],
  },
  {
    region: 'Brasil',
    laws: [
      {
        name: 'Art. 154-A Código Penal',
        summary: 'Invasão de dispositivo informático. Pena de prisión de 1 a 4 años, multa.',
      },
      {
        name: 'Marco Civil da Internet (Ley 12.965/2014)',
        summary: 'Marco regulatorio de internet en Brasil.',
      },
    ],
  },
  {
    region: 'México',
    laws: [
      {
        name: 'Art. 269 Código Penal Federal',
        summary:
          'Acceso ilícito a sistemas computacionales. Pena de prisión de 3 meses a 2 años, multa.',
      },
    ],
  },
  {
    region: 'Argentina',
    laws: [
      {
        name: 'Art. 153-157 bis Código Penal',
        summary: 'Delitos contra la integridad de sistemas informáticos.',
      },
    ],
  },
  {
    region: 'Chile',
    laws: [
      {
        name: 'Ley 19.223',
        summary:
          'Delitos informáticos. Pena de presidio menor en su grado medio (541 días a 3 años).',
      },
    ],
  },
  {
    region: 'Perú',
    laws: [
      {
        name: 'Art. 186-A Código Penal',
        summary:
          'Delitos contra la intimidad, el secreto de las comunicaciones y la inviolabilidad de las comunicaciones. Pena de prisión de 1 a 4 años.',
      },
    ],
  },
  {
    region: 'Global',
    laws: [
      { name: 'US: CFAA, 18 U.S.C. § 1030', summary: 'Computer Fraud and Abuse Act.' },
      { name: 'EU: Directive 2013/40/EU', summary: 'Attacks against information systems.' },
    ],
  },
];

export const FULL_DISCLAIMER_TEXT = `${DISCLAIMER_INTRO}

${DISCLAIMER_OBLIGATIONS.map((o, i) => `${i + 1}. ${o}`).join('\n')}

Applicable laws (LATAM + Global):
${DISCLAIMER_LAWS.map(
  (r) =>
    `${r.region}:\n${r.laws.map((l) => `  • ${l.name} — ${l.summary}`).join('\n')}`,
).join('\n\n')}

By clicking "Confirm + Run" you acknowledge all of the above.
`;
