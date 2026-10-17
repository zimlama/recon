/** @type {import('next').NextConfig} */
const nextConfig = {
  // Standalone output for Docker (smaller image)
  output: 'standalone',

  // Type-safe routes
  experimental: {
    typedRoutes: true,
  },

  // Public env vars
  env: {
    NEXT_PUBLIC_APP_NAME: process.env.NEXT_PUBLIC_APP_NAME || 'zimlama recon',
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  },

  // Disable telemetry
  productionBrowserSourceMaps: false,

  // 2026-10-14 fix: reverse-proxy /api/* to the FastAPI backend on the
  // compose network. Replaces the `proxy_pass http://backend:8000;` that
  // nginx did before the runner rewrite (nginx no longer exists in the
  // standalone-node runner). The backend hostname can be overridden at
  // build time via the REWRITE_API_TARGET env var; default is the
  // docker-compose service name `backend`.
  async rewrites() {
    const target = process.env.REWRITE_API_TARGET || 'http://backend:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${target}/api/:path*`,
      },
    ];
  },

  // Security headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
