import { redactUrl, type PaymentExtractRequest, type PaymentExtraction } from '@authentik/shared';
import { forbidden, HttpError, unavailable } from '../../lib/errors.js';
import { newId, type Clock } from '../../lib/ids.js';
import type { AuditLog } from '../../security/audit/index.js';
import { validateTargetUrl } from '../../security/url-validation/index.js';
import { WorkerUnavailableError, type SandboxWorker, type WorkerExtraction } from '../../sandbox-control/workers/client.js';
import type { SandboxService } from '../../sandbox-control/sessions/service.js';

const TTL_MS = 10 * 60_000;
const MAX_PER_USER = 20;

interface Held {
  uid: string;
  result: WorkerExtraction;
  expiresAt: number;
}

/**
 * Reads the amount and recipient from a payment page. The page is rendered
 * only inside the isolated Sandbox worker — never on the API — because it is
 * untrusted and often needs JavaScript to show its total.
 *
 * The full page URL can carry payment-session tokens, so it never goes to the
 * phone: it is held here for a short time and referenced by `extractionId`.
 * In memory per instance, like live Sandbox sessions (see architecture.md).
 */
export class PaymentExtractionService {
  private readonly held = new Map<string, Held>();

  constructor(
    private readonly deps: { worker: SandboxWorker; sandbox: SandboxService; audit: AuditLog; clock: Clock },
  ) {}

  async extract(uid: string, req: PaymentExtractRequest): Promise<PaymentExtraction> {
    const result = 'sandboxSessionId' in req ? await this.deps.sandbox.readPayment(uid, req.sandboxSessionId) : await this.fromUrl(req.checkoutUrl);
    this.prune();
    const mine = [...this.held.entries()].filter(([, h]) => h.uid === uid);
    if (mine.length >= MAX_PER_USER) this.held.delete(mine[0]![0]);

    const extractionId = newId();
    const expiresAt = this.deps.clock.now().getTime() + TTL_MS;
    this.held.set(extractionId, { uid, result, expiresAt });
    const url = new URL(result.url);
    this.deps.audit.record({ action: 'payment_check.created', uid, hostname: url.hostname, outcome: `extracted_${result.confidence}` });
    return {
      extractionId,
      displayUrl: redactUrl(url),
      pageHost: url.hostname,
      pageTitle: result.title,
      recipientName: result.recipientName,
      amountMinor: result.amountMinor,
      currency: result.currency,
      confidence: result.confidence,
      amountCandidates: result.amountCandidates,
      recipientCandidates: result.recipientCandidates,
      notes: result.notes,
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }

  /** The held extraction, if it exists, is the caller's, and hasn't expired. */
  get(uid: string, extractionId: string): WorkerExtraction | null {
    this.prune();
    const h = this.held.get(extractionId);
    return h && h.uid === uid ? h.result : null;
  }

  private async fromUrl(input: string): Promise<WorkerExtraction> {
    const target = validateTargetUrl(input);
    if (!target.allowed) throw forbidden('target_blocked', target.blockMessage);
    const { worker } = this.deps;
    if (!worker.configured || !worker.extractFromUrl) {
      throw unavailable('extraction_unavailable', 'Reading the page needs the Sandbox, which isn’t available right now. Enter the details yourself.');
    }
    try {
      return await worker.extractFromUrl(target.url.href);
    } catch (err) {
      if (err instanceof HttpError) throw err;
      const reason = err instanceof WorkerUnavailableError ? err.reason : 'unknown';
      if (reason === 'capacity') throw unavailable('extraction_busy', 'Authentik is busy reading other pages. Try again in a moment.');
      throw unavailable('page_unreadable', 'The page could not be read. Enter the details yourself instead.');
    }
  }

  private prune() {
    const now = this.deps.clock.now().getTime();
    for (const [id, h] of this.held) if (h.expiresAt <= now) this.held.delete(id);
  }
}
