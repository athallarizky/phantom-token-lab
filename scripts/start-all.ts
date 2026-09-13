/**
 * scripts/start-all.ts — run the whole lab with one command.
 *
 * Spawns the three services as child processes, prefixes every log line with
 * the service's color so the whole mesh is visible in ONE terminal, waits for
 * each /healthz before declaring ready, and kills them all on Ctrl+C.
 */
import { spawn, type ChildProcess } from 'node:child_process';

type ServiceSpec = {
  name: string;
  script: string;
  color: (text: string) => string;
  healthUrl: string;
  role: string;
};

const SERVICES: ServiceSpec[] = [
  {
    name: 'gateway',
    script: 'apps/gateway/server.ts',
    color: (t) => `\x1b[36m${t}\x1b[0m`,
    healthUrl: 'http://127.0.0.1:3000/healthz',
    role: 'edge — client entrypoint, opaque token lives here',
  },
  {
    name: 'prompt-service',
    script: 'apps/prompt-service/server.ts',
    color: (t) => `\x1b[35m${t}\x1b[0m`,
    healthUrl: 'http://127.0.0.1:3001/healthz',
    role: 'internal — verifies JWT, decides allowed_models',
  },
  {
    name: 'quota-service',
    script: 'apps/quota-service/server.ts',
    color: (t) => `\x1b[33m${t}\x1b[0m`,
    healthUrl: 'http://127.0.0.1:3002/healthz',
    role: 'internal — crown jewels, deducts credits',
  },
];

const dim = (text: string) => `\x1b[2m${text}\x1b[0m`;
const bold = (text: string) => `\x1b[1m${text}\x1b[0m`;

function forwardLines(prefix: string, chunk: Buffer): void {
  for (const line of chunk.toString('utf8').split('\n')) {
    if (line.trim().length > 0) console.log(`${prefix} ${line}`);
  }
}

/** Readiness gate: poll /healthz until it answers (or the child dies, or timeout). */
async function waitForHealth(url: string, child: ChildProcess, timeoutMs = 15_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) return false; // died while starting
    try {
      const response = await fetch(url);
      if (response.ok) return true;
    } catch {
      // not up yet — keep polling
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return false;
}

const children: ChildProcess[] = [];
let shuttingDown = false;

/** Kill every child (one died / unhealthy / Ctrl+C) — never leave orphans holding ports. */
function killAllChildren(): void {
  shuttingDown = true;
  for (const child of children) child.kill('SIGTERM');
}

async function main(): Promise<void> {
  console.log(bold('\n▶ starting phantom-token-lab (3 services)…\n'));

  for (const spec of SERVICES) {
    // 'tsx' resolves because npm puts node_modules/.bin on PATH for script processes.
    const child = spawn('tsx', [spec.script], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    const prefix = spec.color(`[${spec.name}]`);
    child.stdout?.on('data', (chunk: Buffer) => forwardLines(prefix, chunk));
    child.stderr?.on('data', (chunk: Buffer) => forwardLines(`\x1b[31m[${spec.name}!]\x1b[0m`, chunk));
    child.on('exit', (code) => {
      console.log(`${prefix} ${dim(`exited (code ${code})`)}`);
      // One dead service = a broken mesh — take the others down with it.
      if (!shuttingDown) {
        console.error(`\x1b[31m[${spec.name}!]\x1b[0m mesh is incomplete — stopping all services`);
        console.error(dim('common cause: EADDRINUSE — port already held by an old process.'));
        console.error(dim('free the ports first:  lsof -ti :3000 :3001 :3002 | xargs kill'));
        killAllChildren();
        process.exitCode = 1;
      }
    });
  }

  console.log(dim('waiting for /healthz on :3000 :3001 :3002 …'));
  const healthy = await Promise.all(SERVICES.map((s, i) => waitForHealth(s.healthUrl, children[i])));

  if (healthy.some((ok) => !ok)) {
    console.error('\n❌ some services failed to become healthy — see logs above\n');
    killAllChildren();
    process.exitCode = 1;
    return;
  }

  console.log(bold('\n✅ phantom-token-lab is UP\n'));
  for (const s of SERVICES) console.log(`  ${s.color(s.name.padEnd(16))} ${dim(s.role)}`);
  console.log(dim(`\n  client entrypoint : http://localhost:3000`));
  console.log(dim(`  try               : curl -s -X POST localhost:3000/auth/login -H 'content-type: application/json' -d '{"username":"athalla","password":"secret"}'`));
  console.log(dim(`  experiments       : npm run test:experiments   (E1–E3)`));
  console.log(dim(`  benchmark         : npm run test:benchmark     (E4)`));
  console.log(dim(`  stop everything   : Ctrl+C\n`));
}

function shutdown(): void {
  killAllChildren();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

void main();
