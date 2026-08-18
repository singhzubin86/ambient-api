/**
 * Transactional email — Resend integration
 * Spec: AMBIENT_PROTOTYPE_SPECS.md R3 SPEC-2
 * Env vars: RESEND_API_KEY, EMAIL_FROM
 */
import { Resend } from 'resend';
import { logger } from './logger';

let _resend: Resend | null = null;

function getResend(): Resend {
  if (!_resend) {
    const apiKey = process.env['RESEND_API_KEY'];
    if (!apiKey) throw new Error('RESEND_API_KEY env var is not set');
    _resend = new Resend(apiKey);
  }
  return _resend;
}

const EMAIL_FROM = process.env['EMAIL_FROM'] ?? 'noreply@mail.chakkde.com';
const PORTAL_BASE_URL = process.env['PORTAL_BASE_URL'] ?? 'https://ambient-portal.fly.dev';

export async function sendVerificationEmail(opts: {
  to: string;
  fullName: string;
  token: string;
}): Promise<void> {
  const link = `${PORTAL_BASE_URL}/verify-email?token=${encodeURIComponent(opts.token)}`;
  const { error } = await getResend().emails.send({
    from: EMAIL_FROM,
    to: opts.to,
    subject: 'Verify your Ambient account',
    text: [
      `Hi ${opts.fullName},`,
      '',
      'Please verify your Ambient account by clicking the link below:',
      '',
      link,
      '',
      'This link expires in 24 hours.',
      '',
      'If you did not sign up for Ambient, you can ignore this email.',
    ].join('\n'),
  });
  if (error) {
    logger.error({ msg: 'Resend email error', error });
    throw new Error(`Email send failed: ${error.message}`);
  }
}
