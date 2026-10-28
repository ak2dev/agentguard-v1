import { execSync } from 'node:child_process';

export const sh = (line: string): string => execSync(line).toString();
