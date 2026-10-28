import { execSync } from 'node:child_process';

export function sh(line: string): string {
  return execSync(line).toString();
}
