/**
 * Node-only DNS checks for the destination policy. Import from
 * `@authentik/shared/net`; the mobile app must not use this entry point.
 *
 * The important property: callers connect to the *validated* address that
 * came out of these functions, never to a second, independent resolution.
 * That closes the DNS-rebinding gap between "check" and "connect".
 */
import { promises as dns, type LookupAddress } from 'node:dns';
import type { LookupFunction } from 'node:net';
import { checkHostname, isIpLiteral, isPublicAddress, type DestinationCheck } from './policy.js';

export type ResolvedDestination =
  | { allowed: true; addresses: LookupAddress[] }
  | (Extract<DestinationCheck, { allowed: false }> & { addresses?: LookupAddress[] })
  | { allowed: false; code: 'dns_failure'; message: string };

export type Resolver = (hostname: string) => Promise<LookupAddress[]>;

const systemResolver: Resolver = (hostname) => dns.lookup(hostname, { all: true, verbatim: true });

/**
 * Resolves a hostname and requires *every* returned address to be public.
 * One private answer is enough to refuse — attackers mix records on purpose.
 */
export async function resolveAndCheck(
  hostname: string,
  resolver: Resolver = systemResolver,
): Promise<ResolvedDestination> {
  const host = hostname.replace(/^\[|\]$/g, '');
  const staticCheck = checkHostname(host);
  if (!staticCheck.allowed) return staticCheck;

  if (isIpLiteral(host)) {
    return { allowed: true, addresses: [{ address: host, family: host.includes(':') ? 6 : 4 }] };
  }

  let addresses: LookupAddress[];
  try {
    addresses = await resolver(host);
  } catch {
    return { allowed: false, code: 'dns_failure', message: 'The website name could not be resolved.' };
  }
  if (addresses.length === 0) {
    return { allowed: false, code: 'dns_failure', message: 'The website name could not be resolved.' };
  }
  if (!addresses.every((a) => isPublicAddress(a.address))) {
    return {
      allowed: false,
      code: 'non_public_address',
      message: 'That website name points to a private or reserved network and cannot be reached.',
      addresses,
    };
  }
  return { allowed: true, addresses };
}

export class DestinationBlockedError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly hostname: string,
  ) {
    super(message);
    this.name = 'DestinationBlockedError';
  }
}

/**
 * A `lookup` for `net.connect` / undici that only ever yields validated
 * public addresses. Note: Node does not call `lookup` for IP-literal hosts,
 * so callers must also run `checkHostname` on the URL before connecting.
 */
export function createSafeLookup(
  resolver: Resolver = systemResolver,
  onBlocked?: (hostname: string, code: string) => void,
): LookupFunction {
  return (hostname, options, callback) => {
    resolveAndCheck(hostname, resolver).then(
      (result) => {
        if (!result.allowed) {
          onBlocked?.(hostname, result.code);
          callback(new DestinationBlockedError(result.code, result.message, hostname), '', 0);
          return;
        }
        const wanted = typeof options === 'object' && options.family ? options.family : 0;
        const usable = wanted ? result.addresses.filter((a) => a.family === wanted) : result.addresses;
        const list = usable.length ? usable : result.addresses;
        if (typeof options === 'object' && options.all) {
          (callback as unknown as (e: null, a: LookupAddress[]) => void)(null, list);
        } else {
          const first = list[0]!;
          callback(null, first.address, first.family);
        }
      },
      (err: Error) => callback(err as NodeJS.ErrnoException, '', 0),
    );
  };
}
