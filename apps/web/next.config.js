const path = require('path');
const { loadEnvConfig } = require('@next/env');

// Next normally searches apps/web. Load the repository-root .env instead.
loadEnvConfig(path.resolve(__dirname, '../..'));

/** @type {import('next').NextConfig} */
const isDevelopment = process.env.NODE_ENV === 'development';

const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  // Keep dev HMR artifacts separate from the production build output.
  distDir: isDevelopment ? '.next-dev' : '.next',
};

module.exports = nextConfig;
