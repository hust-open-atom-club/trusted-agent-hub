const fs = require('fs');
const path = require('path');
const { loadEnvConfig } = require('@next/env');

const webRoot = path.resolve(__dirname, '..');
const repositoryRoot = path.resolve(webRoot, '../..');
loadEnvConfig(repositoryRoot);

const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000').replace(/\/+$/, '');
const webUrl = (process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000').replace(/\/+$/, '');
const allowHttpFlag = apiUrl.startsWith('http://') ? ' --allow-http' : '';

const templatePath = path.join(webRoot, 'templates', 'install-guide.md');
const outputPath = path.join(webRoot, 'public', 'install', 'tah.md');
const rendered = fs.readFileSync(templatePath, 'utf8')
  .replaceAll('{{TAH_API_URL}}', apiUrl)
  .replaceAll('{{TAH_WEB_URL}}', webUrl)
  .replaceAll('{{TAH_ALLOW_HTTP_FLAG}}', allowHttpFlag);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, rendered, 'utf8');
