"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeEmail = exports.validateEmail = exports.getCurrentTimestamp = void 0;
exports.sendTransactionalEmail = sendTransactionalEmail;
exports.sendLicenseKeyEmail = sendLicenseKeyEmail;
const getCurrentTimestamp = () => new Date().toISOString();
exports.getCurrentTimestamp = getCurrentTimestamp;
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};
exports.validateEmail = validateEmail;
const sanitizeEmail = (email) => email.trim().toLowerCase();
exports.sanitizeEmail = sanitizeEmail;
async function sendTransactionalEmail({ to, subject, text, html, }) {
    const apiKey = process.env.RESEND_API_KEY;
    const from = process.env.TRANSACTIONAL_EMAIL_FROM ?? 'Passa <support@usepassa.com>';
    if (!apiKey) {
        console.log(`[email:skip] ${subject} -> ${to}\n${text}`);
        return { sent: false, skipped: true };
    }
    const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            from,
            to,
            subject,
            text,
            ...(html ? { html } : {}),
        }),
    });
    if (!response.ok) {
        const body = await response.text().catch(() => '');
        return {
            sent: false,
            error: `Email provider failed (${response.status}) ${body}`.trim(),
        };
    }
    return { sent: true };
}
async function sendLicenseKeyEmail(input) {
    const planLabel = input.plan.replace(/_/g, ' ');
    return sendTransactionalEmail({
        to: input.email,
        subject: 'Your Passa License Key',
        text: [
            'Thanks for choosing Passa Pro.',
            '',
            `Plan: ${planLabel}`,
            `License key: ${input.licenseKey}`,
            '',
            'Open Passa, create or unlock your vault, then paste this key when asked to activate Pro.',
            '',
            'If you need help, reply to support@usepassa.com.',
        ].join('\n'),
        html: `
      <div style="font-family:Arial,sans-serif;line-height:1.55;color:#111827">
        <h2>Your Passa License Key</h2>
        <p>Thanks for choosing Passa Pro.</p>
        <p><strong>Plan:</strong> ${planLabel}</p>
        <p><strong>License key:</strong></p>
        <p style="font-size:18px;font-weight:700;letter-spacing:0.04em;background:#f3f4f6;padding:12px 14px;border-radius:6px">${input.licenseKey}</p>
        <p>Open Passa, create or unlock your vault, then paste this key when asked to activate Pro.</p>
        <p>If you need help, email <a href="mailto:support@usepassa.com">support@usepassa.com</a>.</p>
      </div>
    `,
    });
}
