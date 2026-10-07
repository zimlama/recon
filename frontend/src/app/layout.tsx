import type { Metadata } from 'next';
import { Plus_Jakarta_Sans, Montserrat, IBM_Plex_Mono } from 'next/font/google';
import './globals.css';
import { BrandHeader } from '@/components/BrandHeader';
import { BrandFooter } from '@/components/BrandFooter';

const plusJakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-titulos',
  display: 'swap',
});

const montserrat = Montserrat({
  subsets: ['latin'],
  weight: ['400', '600'],
  variable: '--font-cuerpo',
  display: 'swap',
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '600'],
  variable: '--font-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'zimlama recon — Phase 1',
  description: 'Self-hosted reconnaissance framework for web applications. Open source. AI-validated.',
  keywords: ['pentest', 'recon', 'OSINT', 'ethical-hacking', 'zimlama'],
  authors: [{ name: 'zimlama' }],
  openGraph: {
    title: 'zimlama recon',
    description: 'Phase 1 ethical hacking reconnaissance framework',
    type: 'website',
  },
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${plusJakarta.variable} ${montserrat.variable} ${ibmPlexMono.variable}`}
    >
      <body className="min-h-screen flex flex-col">
        <BrandHeader />
        <main className="flex-1 container mx-auto px-4 py-8 max-w-7xl">{children}</main>
        <BrandFooter />
      </body>
    </html>
  );
}
