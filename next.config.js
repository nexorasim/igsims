/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  assetPrefix: process.env.NODE_ENV === 'production' ? 'https://bamboo-reason-483913-i4.web.app' : '',
  basePath: '',
  distDir: 'out',
  experimental: {
    appDir: true
  }
}

module.exports = nextConfig