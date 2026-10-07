import Link from 'next/link';

export function BrandFooter() {
  return (
    <footer className="border-t border-zimlama-gris/30 mt-12">
      <div className="container mx-auto px-4 max-w-7xl py-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-zimlama-gris">
        <div>
          © 2026 zimlama · Apache-2.0 · v0.1.0
        </div>
        <div className="flex gap-4">
          <Link
            href="https://github.com/zimlama/recon"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-zimlama-rojo no-underline"
          >
            GitHub
          </Link>
          <Link href="/disclaimer" className="hover:text-zimlama-rojo no-underline">
            Disclaimer
          </Link>
        </div>
      </div>
    </footer>
  );
}
