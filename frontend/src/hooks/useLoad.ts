import { DependencyList, useEffect } from 'react';

/**
 * Runs `load` on mount and whenever `deps` change, and again every `every` ms when given. Used for fetching: the
 * state updates happen when the request finishes, not during the effect, which is what the lint rule for synchronous
 * setState-in-effect cannot see through a plain function. `enabled: false` skips everything (e.g. before sign-in).
 */
export function useLoad(load: () => unknown, deps: DependencyList, options: { every?: number; enabled?: boolean } = {}): void {
  const { every, enabled = true } = options;
  useEffect(() => {
    if (!enabled) return undefined;
    void load();
    if (!every) return undefined;
    const id = setInterval(() => void load(), every);
    return () => clearInterval(id);
    // `load` and `every` are deliberately the caller's to list in `deps`, exactly as with useEffect.
    // oxlint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps]);
}
