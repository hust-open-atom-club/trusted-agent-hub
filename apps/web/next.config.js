/** @type {import('next').NextConfig} */
const isDevelopment = process.env.NODE_ENV === 'development';

const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  // Keep dev HMR artifacts separate from the production build output.
  distDir: isDevelopment ? '.next-dev' : '.next',
};

module.exports = nextConfig;
