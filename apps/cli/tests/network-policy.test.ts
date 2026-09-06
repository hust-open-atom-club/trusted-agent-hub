import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { getApiBase } from '../src/network-policy';


// The published CLI must work against the public Hub without requiring users
// to configure a local IP or run `tah use` first. Use an empty temporary home
// directory so the assertion never reads the developer's real CLI config, and
// clear API URL environment variables so local checkout settings cannot leak.
const temporaryHome = fs.mkdtempSync(
  path.join(os.tmpdir(), 'trusted-agent-hub-network-policy-'),
);
const previousApiUrl = process.env.TRUSTED_AGENT_HUB_API_URL;
const previousWebApiUrl = process.env.NEXT_PUBLIC_API_URL;
try {
  delete process.env.TRUSTED_AGENT_HUB_API_URL;
  delete process.env.NEXT_PUBLIC_API_URL;
  assert.strictEqual(
    getApiBase(temporaryHome),
    'https://tah.openatom.club',
  );
  console.log('  ✓ defaults to the public TrustedAgentHub domain');
} finally {
  if (previousApiUrl === undefined) {
    delete process.env.TRUSTED_AGENT_HUB_API_URL;
  } else {
    process.env.TRUSTED_AGENT_HUB_API_URL = previousApiUrl;
  }
  if (previousWebApiUrl === undefined) {
    delete process.env.NEXT_PUBLIC_API_URL;
  } else {
    process.env.NEXT_PUBLIC_API_URL = previousWebApiUrl;
  }
  fs.rmSync(temporaryHome, { recursive: true, force: true });
}
