import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  findRepositoryRoot,
  loadRepositoryEnvironment,
} from '../src/load-root-env';


console.log('CLI Environment Configuration Tests\n');

const temporaryRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), 'trusted-agent-hub-cli-env-'),
);
const nestedDirectory = path.join(temporaryRoot, 'apps', 'cli', 'src');
fs.mkdirSync(nestedDirectory, { recursive: true });
fs.writeFileSync(path.join(temporaryRoot, '.env.example'), '', 'utf8');
fs.writeFileSync(path.join(temporaryRoot, 'docker-compose.yml'), 'services: {}\n', 'utf8');
fs.writeFileSync(
  path.join(temporaryRoot, 'apps', 'cli', 'package.json'),
  '{}\n',
  'utf8',
);
fs.writeFileSync(
  path.join(temporaryRoot, '.env'),
  [
    'TRUSTED_AGENT_HUB_API_URL=https://hub.example.com',
    'TRUSTED_AGENT_HUB_TOKEN=test-token',
    'TAH_TEST_DOTENV_VALUE=from-root-env',
    '',
  ].join('\n'),
  'utf8',
);

const previousValue = process.env.TAH_TEST_DOTENV_VALUE;
const previousApiUrl = process.env.TRUSTED_AGENT_HUB_API_URL;
const previousToken = process.env.TRUSTED_AGENT_HUB_TOKEN;
try {
  assert.strictEqual(findRepositoryRoot([nestedDirectory]), temporaryRoot);
  console.log('  ✓ repository root is discovered from a nested CLI path');

  delete process.env.TAH_TEST_DOTENV_VALUE;
  delete process.env.TRUSTED_AGENT_HUB_API_URL;
  delete process.env.TRUSTED_AGENT_HUB_TOKEN;
  assert.strictEqual(
    loadRepositoryEnvironment([nestedDirectory]),
    temporaryRoot,
  );
  assert.strictEqual(process.env.TAH_TEST_DOTENV_VALUE, 'from-root-env');
  assert.strictEqual(
    process.env.TRUSTED_AGENT_HUB_API_URL,
    'https://hub.example.com',
  );
  assert.strictEqual(process.env.TRUSTED_AGENT_HUB_TOKEN, 'test-token');
  console.log('  ✓ repository-root .env is loaded');

  process.env.TAH_TEST_DOTENV_VALUE = 'from-process';
  loadRepositoryEnvironment([nestedDirectory]);
  assert.strictEqual(process.env.TAH_TEST_DOTENV_VALUE, 'from-process');
  console.log('  ✓ explicit process environment retains priority');
} finally {
  if (previousValue === undefined) {
    delete process.env.TAH_TEST_DOTENV_VALUE;
  } else {
    process.env.TAH_TEST_DOTENV_VALUE = previousValue;
  }
  if (previousApiUrl === undefined) {
    delete process.env.TRUSTED_AGENT_HUB_API_URL;
  } else {
    process.env.TRUSTED_AGENT_HUB_API_URL = previousApiUrl;
  }
  if (previousToken === undefined) {
    delete process.env.TRUSTED_AGENT_HUB_TOKEN;
  } else {
    process.env.TRUSTED_AGENT_HUB_TOKEN = previousToken;
  }
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}

console.log('\n  ✓ All CLI environment configuration tests passed!\n');
