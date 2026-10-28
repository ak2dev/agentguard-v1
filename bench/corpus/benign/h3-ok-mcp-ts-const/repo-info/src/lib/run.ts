import { execSync } from 'node:child_process';

export function runCmd(cmd: string): string {
  return execSync(cmd).toString();
}
