import ipaddr from 'ipaddr.js';

/**
 * Destination policy shared by the scanner (backend) and the Sandbox egress
 * proxy (worker). Everything here is pure; DNS-based checks live in `net.ts`.
 *
 * The rule is allow-list shaped: only public unicast addresses on the standard
 * web ports are reachable. Anything else — loopback, private ranges, link-local
 * (cloud metadata), CGNAT, multicast, reserved — is refused.
 */

export const ALLOWED_PORTS = new Set([80, 443]);

export type DestinationBlockCode =
  | 'port_not_allowed'
  | 'blocked_hostname'
  | 'single_label_hostname'
  | 'non_public_address';

export type DestinationCheck =
  | { allowed: true }
  | { allowed: false; code: DestinationBlockCode; message: string };

const BLOCKED_SUFFIXES = [
  'localhost',
  'local',
  'internal',
  'intranet',
  'lan',
  'home',
  'corp',
  'home.arpa',
  'localdomain',
  'in-addr.arpa',
  'ip6.arpa',
];

const BLOCKED_HOSTS = new Set(['metadata', 'metadata.google.internal', 'instance-data']);

/** True only for globally routable unicast addresses. */
export function isPublicAddress(address: string): boolean {
  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    // `process` unwraps IPv4-mapped IPv6 (::ffff:127.0.0.1) to plain IPv4.
    parsed = ipaddr.process(address);
  } catch {
    return false;
  }
  return parsed.range() === 'unicast';
}

export function isIpLiteral(hostname: string): boolean {
  const bare = hostname.replace(/^\[|\]$/g, '');
  return ipaddr.isValid(bare) && (ipaddr.IPv4.isValidFourPartDecimal(bare) || bare.includes(':'));
}

export function effectivePort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
}

/** Checks a URL against the static destination policy (no DNS). */
export function checkStaticDestination(url: URL): DestinationCheck {
  const port = effectivePort(url);
  if (!ALLOWED_PORTS.has(port)) {
    return {
      allowed: false,
      code: 'port_not_allowed',
      message: `Port ${port} is not permitted. Only standard web ports (80, 443) can be reached.`,
    };
  }
  return checkHostname(url.hostname);
}

export function checkHostname(rawHostname: string): DestinationCheck {
  const hostname = rawHostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');

  if (isIpLiteral(hostname)) {
    return isPublicAddress(hostname)
      ? { allowed: true }
      : {
          allowed: false,
          code: 'non_public_address',
          message: 'That address points to a private or reserved network and cannot be reached.',
        };
  }

  if (BLOCKED_HOSTS.has(hostname) || BLOCKED_SUFFIXES.some((s) => hostname === s || hostname.endsWith(`.${s}`))) {
    return {
      allowed: false,
      code: 'blocked_hostname',
      message: 'That address refers to a local or internal network name and cannot be reached.',
    };
  }

  if (!hostname.includes('.')) {
    return {
      allowed: false,
      code: 'single_label_hostname',
      message: 'That address is not a public website name.',
    };
  }

  return { allowed: true };
}
