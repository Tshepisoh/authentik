import type { Assessment, CheckRun, Finding, Verdict } from '@authentik/shared';

export type Subject = 'website' | 'payment' | 'sandbox' | 'notification';

/**
 * Deterministic, evidence-grounded explanation text.
 *
 * An optional AI layer may later rephrase `explanation` for readability, but it
 * receives the finished Assessment and may only rewrite prose: it must not add
 * findings, change the verdict, or soften a hard block.
 */
export function explain(
  subject: Subject,
  verdict: Verdict,
  findings: Finding[],
  checks: CheckRun[],
  completeness: Assessment['completeness'],
): Pick<Assessment, 'headline' | 'explanation' | 'recommendedActions'> {
  const explanation: string[] = [];
  const concerns = findings.filter((f) => f.kind === 'confirmed_threat' || f.kind === 'suspicious_indicator');
  const unknowns = findings.filter((f) => f.kind === 'unknown');

  for (const f of concerns.slice(0, 6)) explanation.push(`${f.title}. ${f.reason}`);
  if (concerns.length > 6) explanation.push(`${concerns.length - 6} further warning(s) are listed in the findings.`);

  const missing = checks.filter((c) => c.status === 'unavailable' || c.status === 'failed');
  for (const c of missing) {
    explanation.push(`We could not complete the ${humanCheck(c.check)} check${c.detail ? ` (${c.detail})` : ''}.`);
  }
  for (const u of unknowns.slice(0, 3)) explanation.push(`${u.title}. ${u.reason}`);

  if (verdict === 'no_obvious_warnings') {
    explanation.push(
      subject === 'payment'
        ? 'The details we could compare match what you expected. This does not prove the payment is safe — confirm with the merchant if anything feels off.'
        : 'Our checks found no known problems. That is not a guarantee of safety, and a padlock (HTTPS) on its own does not prove a site is legitimate.',
    );
  }
  if (verdict === 'inconclusive') {
    explanation.push('Because some checks could not run, do not treat this result as verified safe.');
  }
  if (completeness === 'partial' && verdict !== 'inconclusive' && verdict !== 'blocked') {
    explanation.push('This assessment is partial: some evidence was unavailable.');
  }

  return {
    headline: HEADLINES[subject][verdict],
    explanation,
    recommendedActions: recommend(subject, verdict, findings),
  };
}

const HEADLINES: Record<Subject, Record<Verdict, string>> = {
  website: {
    high_risk: 'This site shows strong signs of fraud. Avoid it.',
    suspicious: 'This site has warning signs. Verify it independently before you trust it.',
    no_obvious_warnings: 'No obvious warnings found. Proceed with normal caution.',
    inconclusive: 'We could not check this site fully. Do not treat it as verified safe.',
    blocked: 'This address could not be scanned.',
  },
  payment: {
    high_risk: 'This payment shows serious warning signs. Do not pay until you have verified it.',
    suspicious: 'This payment does not match what you expected. Stop and verify before paying.',
    no_obvious_warnings: 'No discrepancy detected between what you expected and what we observed.',
    inconclusive: 'Verification incomplete — we could not confirm enough of the payment details.',
    blocked: 'This payment address could not be checked.',
  },
  notification: {
    high_risk: 'This notification looks like a scam. Don’t act on it.',
    suspicious: 'This notification has warning signs. Check it another way before you act.',
    no_obvious_warnings: 'No obvious warnings in this notification or its links. That doesn’t prove it’s genuine.',
    inconclusive: 'We couldn’t fully check the links in this notification. Don’t treat it as verified.',
    blocked: 'This notification couldn’t be checked.',
  },
  sandbox: {
    high_risk: 'The Sandbox observed high-risk behaviour from this site.',
    suspicious: 'The Sandbox observed behaviour that needs your attention.',
    no_obvious_warnings: 'The Sandbox did not observe concerning behaviour during this session.',
    inconclusive: 'The Sandbox session ended before enough could be observed.',
    blocked: 'The Sandbox refused to open this site.',
  },
};

const ACTIONS_BY_CODE: Record<string, string> = {
  reputation_match: 'Do not enter any personal, login or payment details on this site.',
  lookalike_domain: 'Type the official address of the brand yourself instead of following this link.',
  brand_on_unofficial_domain: 'Type the official address of the brand yourself instead of following this link.',
  brand_in_subdomain: 'Look at the real domain (just before the final ".com", ".co.za", etc.) — it is not the brand it claims to be.',
  embedded_credentials: 'Be wary of the message that sent you this link; it was crafted to hide the real destination.',
  credential_form_offsite: 'Never sign in through this page. Open the official app or website directly.',
  recently_registered: 'New sites are not necessarily malicious, but check reviews and the company’s registration before buying.',
  payment_recipient_mismatch: 'Contact the merchant through their official channels to confirm who should receive payment.',
  payment_amount_mismatch: 'Do not authorise a payment for an amount you did not agree to.',
  payment_currency_mismatch: 'Do not authorise a payment in a currency you did not expect.',
  unrecognised_payment_redirect: 'Go back to the merchant’s official site and restart checkout from there.',
  blocked_destination: 'The site tried to reach a destination Authentik does not allow. Treat it with suspicion.',
  download_blocked: 'Do not download files from this site onto your phone.',
  isolation_failure: 'The session was stopped for your safety. Do not open this site directly.',
  payment_claim: 'Check the payment in your own banking app before you hand over anything. A notification isn’t proof of payment.',
  payment_claim_release: 'Don’t release the goods until the money shows in your own banking app.',
  credential_request: 'Never share your PIN, OTP or password. Call your bank on the number on the back of your card.',
  verify_via_link: 'Open the official app or website yourself instead of using the link.',
  delivery_fee_link: 'Check the delivery in the courier’s official app or website.',
  refund_link: 'Contact the company directly. Real refunds don’t need you to sign in through a link.',
  link_not_public: 'Don’t open the link. It points to a private or reserved address.',
};

function recommend(subject: Subject, verdict: Verdict, findings: Finding[]): string[] {
  const actions = new Set<string>();
  for (const f of findings) {
    if (f.kind === 'reassurance') continue;
    const a = ACTIONS_BY_CODE[f.code];
    if (a) actions.add(a);
  }
  switch (verdict) {
    case 'high_risk':
      actions.add(
        subject === 'payment' ? 'Cancel this payment.' : subject === 'notification' ? 'Don’t reply, call back or open the links.' : 'Close the site and do not return to it.',
      );
      actions.add('If you already entered details, contact your bank and change affected passwords now.');
      break;
    case 'suspicious':
      actions.add('Verify independently — use the official app or a bookmarked address.');
      if (subject === 'website') actions.add('If you must look, open it in the Authentik Sandbox rather than your own browser.');
      if (subject === 'notification') actions.add('Contact the sender through a number or app you already trust.');
      break;
    case 'inconclusive':
      actions.add('Try again later, or verify the site through another trusted source.');
      break;
    case 'no_obvious_warnings':
      actions.add(subject === 'payment' ? 'Review the final amount and recipient on your bank’s screen before approving.' : 'Proceed cautiously and only share details the site genuinely needs.');
      break;
    case 'blocked':
      actions.add('Check that you copied the full public website address.');
      break;
  }
  return [...actions];
}

function humanCheck(check: string): string {
  const names: Record<string, string> = {
    'reputation.google_safe_browsing': 'threat-reputation',
    'reputation.threat_feeds': 'threat feed',
    'reputation.local_blocklist': 'blocklist',
    page_evidence: 'page content',
    domain_registration: 'domain registration',
    payment_observation: 'payment observation',
    lookalike: 'impersonation',
  };
  return names[check] ?? check.replace(/[._]/g, ' ');
}
