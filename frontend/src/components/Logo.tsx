interface LogoProps {
  variant?: 'isotipo' | 'horizontal' | 'vertical' | 'watermark';
  size?: number;
  className?: string;
}

/**
 * zimlama logo — GIR-style robot head with magnifying glass.
 * SVG so it scales perfectly + currentColor for theming.
 */
export function Logo({ variant = 'isotipo', size = 32, className }: LogoProps) {
  if (variant === 'watermark') {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 64 64"
        width={size * 4}
        height={size * 4}
        className={className}
        style={{ opacity: 0.05 }}
        aria-label="zimlama watermark"
        role="img"
      >
        <RobotHead fill="currentColor" />
      </svg>
    );
  }

  if (variant === 'horizontal') {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 200 64"
        width={size * 4}
        height={size}
        className={className}
        aria-label="zimlama recon"
        role="img"
      >
        <RobotHead size={48} fill="var(--zimlama-piel)" />
        <text
          x="60"
          y="42"
          fontFamily="var(--font-titulos)"
          fontSize="28"
          fontWeight="700"
          fontStyle="italic"
          fill="currentColor"
        >
          zimlama
        </text>
      </svg>
    );
  }

  if (variant === 'vertical') {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 100 130"
        width={size * 2}
        height={size * 2.5}
        className={className}
        aria-label="zimlama recon"
        role="img"
      >
        <RobotHead x={18} size={64} fill="var(--zimlama-piel)" />
        <text
          x="50"
          y="100"
          textAnchor="middle"
          fontFamily="var(--font-titulos)"
          fontSize="16"
          fontWeight="700"
          fontStyle="italic"
          fill="currentColor"
        >
          zimlama
        </text>
        <text
          x="50"
          y="118"
          textAnchor="middle"
          fontFamily="var(--font-cuerpo)"
          fontSize="9"
          fill="currentColor"
          opacity="0.6"
        >
          RECON
        </text>
      </svg>
    );
  }

  // Default: isotipo
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width={size}
      height={size}
      className={className}
      aria-label="zimlama"
      role="img"
    >
      <RobotHead fill="var(--zimlama-piel)" />
    </svg>
  );
}

function RobotHead({ x = 0, y = 0, size = 64, fill = 'currentColor' }: {
  x?: number;
  y?: number;
  size?: number;
  fill?: string;
}) {
  return (
    <g transform={`translate(${x}, ${y})`}>
      {/* Antenna */}
      <line x1={size / 2} y1="4" x2={size / 2} y2="14" stroke={fill} strokeWidth="2" />
      <circle cx={size / 2} cy="4" r="3" fill="var(--zimlama-rojo)" />

      {/* Head (rounded rectangle) */}
      <rect
        x="8"
        y="14"
        width={size - 16}
        height={size - 22}
        rx="8"
        ry="8"
        fill={fill}
        stroke="var(--zimlama-negro)"
        strokeWidth="1.5"
      />

      {/* Magnifying glass (the "eye") */}
      <circle
        cx={size / 2}
        cy={size / 2 - 4}
        r="9"
        fill="var(--zimlama-blanco)"
        stroke="var(--zimlama-negro)"
        strokeWidth="2"
      />
      <line
        x1={size / 2 + 6}
        y1={size / 2 + 2}
        x2={size / 2 + 12}
        y2={size / 2 + 8}
        stroke="var(--zimlama-negro)"
        strokeWidth="2.5"
        strokeLinecap="round"
      />

      {/* Mouth (small line) */}
      <line
        x1={size / 2 - 6}
        y1={size - 14}
        x2={size / 2 + 6}
        y2={size - 14}
        stroke="var(--zimlama-negro)"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </g>
  );
}
