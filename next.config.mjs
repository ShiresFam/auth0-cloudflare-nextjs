/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  // Configure for Cloudflare Workers
  experimental: {
    runtime: 'edge',
    serverComponents: true,
  },
  // Ensure compatibility with Cloudflare Workers
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.output.webassemblyModuleFilename = 'static/wasm/[modulehash].wasm'
    }
    config.experiments = { ...config.experiments, asyncWebAssembly: true }
    return config
  },
}

export default nextConfig

