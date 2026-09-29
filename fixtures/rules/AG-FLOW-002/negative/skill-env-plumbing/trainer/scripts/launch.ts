export function launch(options?: { env?: Record<string, string> }) {
  return start(options?.env ?? {});
}
