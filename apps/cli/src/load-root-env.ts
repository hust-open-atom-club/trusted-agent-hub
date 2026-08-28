import * as fs from 'node:fs';
import * as path from 'node:path';
import { config as loadDotenv } from 'dotenv';


function isRepositoryRoot(candidate: string): boolean {
  return (
    fs.existsSync(path.join(candidate, '.env.example'))
    && fs.existsSync(path.join(candidate, 'docker-compose.yml'))
    && fs.existsSync(path.join(candidate, 'apps', 'cli', 'package.json'))
  );
}


export function findRepositoryRoot(
  startDirectories: readonly string[] = [process.cwd(), __dirname],
): string | null {
  const visited = new Set<string>();
  for (const startDirectory of startDirectories) {
    let candidate = path.resolve(startDirectory);
    while (!visited.has(candidate)) {
      visited.add(candidate);
      if (isRepositoryRoot(candidate)) return candidate;
      const parent = path.dirname(candidate);
      if (parent === candidate) break;
      candidate = parent;
    }
  }
  return null;
}


export function loadRepositoryEnvironment(
  startDirectories?: readonly string[],
): string | null {
  const repositoryRoot = findRepositoryRoot(startDirectories);
  if (!repositoryRoot) return null;

  const envFile = path.join(repositoryRoot, '.env');
  if (fs.existsSync(envFile)) {
    // Explicit shell/CI values retain priority over the checkout-local file.
    loadDotenv({ path: envFile, override: false });
  }
  return repositoryRoot;
}


loadRepositoryEnvironment();
