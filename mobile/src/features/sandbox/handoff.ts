import type { SandboxSessionResponse } from '@authentik/shared';

/**
 * The view token is a credential, so it is passed between screens in memory —
 * never through route params, which can end up in navigation state and logs.
 */
let pending: SandboxSessionResponse | null = null;

export const sandboxHandoff = {
  put(s: SandboxSessionResponse) {
    pending = s;
  },
  take(sessionId: string): SandboxSessionResponse | null {
    if (pending?.sessionId !== sessionId) return null;
    const s = pending;
    pending = null;
    return s;
  },
};
