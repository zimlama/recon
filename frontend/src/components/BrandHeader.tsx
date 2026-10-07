import Link from 'next/link';
import { Logo } from './Logo';

export function BrandHeader() {
  return (
    <header className="border-b border-zimlama-gris/30 bg-zimlama-negro/95 backdrop-blur sticky top-0 z-50">
      <div className="container mx-auto px-4 max-w-7xl flex items-center justify-between h-16">
        <Link href="/" className="flex items-center gap-3 no-underline">
          <Logo variant="isotipo" size={32} />
          <span className="font-titulos font-bold text-zimlama-blanco text-lg">zimlama recon</span>
        </Link>
        <nav className="flex items-center gap-6">
          <Link
            href="/"
            className="text-zimlama-blanco/80 hover:text-zimlama-rojo no-underline text-sm"
          >
            Dashboard
          </Link>
          <Link
            href="/jobs"
            className="text-zimlama-blanco/80 hover:text-zimlama-rojo no-underline text-sm"
          >
            Jobs
          </Link>
          <Link
            href="/modules"
            className="text-zimlama-blanco/80 hover:text-zimlama-rojo no-underline text-sm"
          >
            Modules
          </Link>
          <Link
            href="/jobs/new"
            className="bg-zimlama-rojo text-zimlama-blanco px-4 py-2 rounded-md text-sm font-titulos font-bold no-underline hover:opacity-90"
          >
            New Job
          </Link>
        </nav>
      </div>
    </header>
  );
}
