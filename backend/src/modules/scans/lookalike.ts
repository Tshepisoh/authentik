import { domainToUnicode } from 'node:url';
import { publicSuffix, registrableDomain, type Finding } from '@authentik/shared';
import { finding } from '../risk-engine/engine.js';
import type { EntityRegistry, KnownEntity } from '../merchant-verification/registry.js';

/** Characters commonly substituted to imitate Latin letters. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x',
  і: 'i', ї: 'i', ј: 'j', ԁ: 'd', ɡ: 'g', ӏ: 'l', ѕ: 's', ԛ: 'q', ԝ: 'w', һ: 'h',
  // Greek
  α: 'a', β: 'b', ε: 'e', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w',
  // Digits and symbols
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's',
  // Latin look-alikes
  ı: 'i', ł: 'l', ø: 'o', đ: 'd', ħ: 'h',
};

/**
 * Reduces a label to a "visual skeleton" so that `tаkеаl0t` (Cyrillic а/е,
 * digit 0) and `take-alot` both compare equal to `takealot`. `i` and `l` are
 * folded together because they are routinely swapped.
 */
export function skeleton(label: string): string {
  const decomposed = label.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '');
  let out = '';
  for (const ch of decomposed) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[il]/g, 'l').replace(/[^a-z0-9]/g, '');
}

export function levenshtein(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const v = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
      cur.push(v);
      rowMin = Math.min(rowMin, v);
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length]!;
}

type Match = { entity: KnownEntity; finding: Finding; rank: number };

/**
 * Looks for a hostname imitating a known merchant, payment provider or bank.
 * A hostname on an entity's official domain yields reassurance instead — and
 * is not checked further, so brands never flag their own subdomains.
 */
export function analyzeImpersonation(hostname: string, registry: EntityRegistry): Finding[] {
  const owner = registry.ownerOf(hostname);
  if (owner) {
    return [
      finding({
        code: 'official_domain',
        source: 'lookalike',
        kind: 'reassurance',
        severity: 'info',
        quality: 'medium',
        title: `Official ${owner.name} domain`,
        reason: `${hostname} belongs to a domain registered to ${owner.name} in Authentik's merchant registry.`,
        data: { entity: owner.id },
      }),
    ];
  }

  const domain = registrableDomain(hostname);
  if (!domain) return [];
  const suffix = publicSuffix(hostname) ?? '';
  const asciiLabel = suffix ? domain.slice(0, -(suffix.length + 1)) : domain;
  const label = domainToUnicode(asciiLabel) || asciiLabel;
  const isIdn = asciiLabel.includes('xn--');
  const subLabels = hostname
    .slice(0, Math.max(0, hostname.length - domain.length - 1))
    .split('.')
    .filter(Boolean)
    .map((l) => domainToUnicode(l) || l);

  const labelSkeleton = skeleton(label);
  const matches: Match[] = [];

  for (const entity of registry.entities) {
    for (const token of entity.brandTokens) {
      const tokenSkeleton = skeleton(token);
      const plain = label.toLowerCase();

      if (plain === token) {
        matches.push(m(entity, 3, {
          code: 'brand_on_unofficial_domain', severity: 'high', quality: 'medium',
          title: `Uses the ${entity.name} name on an unofficial domain`,
          reason: `${domain} uses the name "${token}" but is not one of ${entity.name}'s known domains (${entity.domains.slice(0, 3).join(', ')}).`,
        }));
      } else if (labelSkeleton === tokenSkeleton) {
        matches.push(m(entity, 4, {
          code: 'lookalike_domain', severity: 'high', quality: 'high',
          title: `Imitates ${entity.name}`,
          reason: `${domain} uses look-alike characters to resemble "${token}"${isIdn ? ' (it contains non-Latin characters that look like Latin letters)' : ''}.`,
        }));
      } else if (token.length >= 5 && withinTypoDistance(labelSkeleton, tokenSkeleton)) {
        matches.push(m(entity, 3, {
          code: 'lookalike_domain', severity: 'high', quality: 'medium',
          title: `Resembles ${entity.name}`,
          reason: `${domain} is one or two characters away from "${token}", a common typo-squatting technique.`,
        }));
      } else if (containsBrand(plain, token)) {
        matches.push(m(entity, 2, {
          code: 'brand_in_domain', severity: 'medium', quality: 'medium',
          title: `Includes the ${entity.name} name`,
          reason: `${domain} contains "${token}" but is not an official ${entity.name} domain. Scammers often add words like "secure" or "deals" to a brand name.`,
        }));
      }

      if (subLabels.some((s) => s.toLowerCase() === token || skeleton(s) === tokenSkeleton)) {
        matches.push(m(entity, 4, {
          code: 'brand_in_subdomain', severity: 'high', quality: 'high',
          title: `Disguised as ${entity.name}`,
          reason: `The address starts with "${token}", but the real domain is ${domain}. Only the part just before the ending (like .com or .co.za) identifies the owner.`,
        }));
      }
    }
  }

  // Keep the strongest finding per entity.
  const best = new Map<string, Match>();
  for (const match of matches) {
    const existing = best.get(match.entity.id);
    if (!existing || match.rank > existing.rank) best.set(match.entity.id, match);
  }
  const findings = [...best.values()].map((x) => x.finding);

  if (isIdn && findings.length === 0) {
    findings.push(
      finding({
        code: 'idn_domain', source: 'lookalike', kind: 'suspicious_indicator', severity: 'low', quality: 'low',
        title: 'Uses international characters',
        reason: `${domain} is written with non-Latin characters (shown as "${label}"). This is normal for many languages but is also used to imitate familiar names.`,
      }),
    );
  }
  return findings;
}

function m(
  entity: KnownEntity,
  rank: number,
  f: Pick<Finding, 'code' | 'severity' | 'quality' | 'title' | 'reason'>,
): Match {
  return {
    entity,
    rank,
    finding: finding({ ...f, source: 'lookalike', kind: 'suspicious_indicator', data: { entity: entity.id } }),
  };
}

function withinTypoDistance(a: string, b: string): boolean {
  const d = levenshtein(a, b, 2);
  return d >= 1 && d <= (b.length >= 8 ? 2 : 1);
}

/** Brand as a distinct part of the label: `takealot-deals`, `securetakealot`, but not `absalom` for `absa`. */
function containsBrand(label: string, token: string): boolean {
  if (!label.includes(token)) return false;
  if (label.split('-').includes(token)) return true;
  return token.length >= 5;
}
