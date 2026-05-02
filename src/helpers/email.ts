export const getCurrentTimestamp = (): string => new Date().toISOString();

export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

export const sanitizeEmail = (email: string): string => email.trim().toLowerCase();

type SendEmailInput = {
  to: string;
  subject: string;
  text: string;
  html?: string;
};

export async function sendTransactionalEmail({
  to,
  subject,
  text,
  html,
}: SendEmailInput): Promise<{ sent: boolean; skipped?: boolean; error?: string }> {
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

export async function sendLicenseKeyEmail(input: {
  email: string;
  licenseKey: string;
  plan: string;
}): Promise<{ sent: boolean; skipped?: boolean; error?: string }> {
  const planLabel =
    {
      annual: 'Annual Pro',
      lifetime: 'Lifetime Pro',
      monthly: 'Monthly Pro',
      biannual: 'Biannual Pro',
      trial_1d: '1-day Pro Trial',
      trial_2w: '2-week Pro Trial',
      trial_3m: '3-month Pro Trial',
      pro: 'Passa Pro',
    }[input.plan] ?? input.plan.replace(/_/g, ' ');

  return sendTransactionalEmail({
    to: input.email,
    subject: 'Your Passa Pro License Key',
    text: [
      'Thanks for choosing Passa Pro!',
      '',
      `Plan: ${planLabel}`,
      `License key: ${input.licenseKey}`,
      '',
      'Next steps:',
      '1. Open the Passa extension',
      '2. Create or unlock your vault',
      '3. Paste this key when asked to activate Pro',
      '',
      'Need help? Contact support@usepassa.com',
    ].join('\n'),
    html: `
      <html>
        <head>
          <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap" rel="stylesheet">
        </head>
        <body style="margin:0;padding:0;background:#ffffff">
          <div style="font-family:'Montserrat',system-ui,-apple-system,sans-serif;background:#ffffff;padding:40px 20px">
            <div style="max-width:580px;margin:0 auto">
              <!-- Header -->
              <div style="text-align:center;margin-bottom:32px">
                <h1 style="margin:0;color:#1f2937;font-size:32px;font-weight:700;letter-spacing:-0.5px">Your License Key</h1>
                <p style="margin:12px 0 0 0;color:#6b7280;font-size:16px;font-weight:400">Passa Pro is ready for your vault</p>
              </div>

              <!-- Main Card -->
              <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:32px;margin-bottom:24px">
                <p style="margin:0 0 24px 0;color:#374151;font-size:15px;line-height:1.6;font-weight:400">Thanks for choosing Passa Pro. Your license key is ready to activate in the Passa extension.</p>

                <!-- Plan Badge -->
                <div style="margin-bottom:24px">
                  <p style="margin:0 0 8px 0;color:#6b7280;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Your Plan</p>
                  <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:6px;padding:12px 16px;display:inline-block">
                    <p style="margin:0;color:#1f2937;font-size:16px;font-weight:600">${planLabel}</p>
                  </div>
                </div>

                <!-- License Key -->
                <div style="margin-bottom:0">
                  <p style="margin:0 0 8px 0;color:#6b7280;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px">License Key</p>
                  <div style="background:#ffffff;border:1px solid #d1d5db;border-radius:6px;padding:16px;font-family:'Courier New',monospace;word-break:break-all">
                    <p style="margin:0;color:#1f2937;font-size:15px;font-weight:600;letter-spacing:0.02em">${input.licenseKey}</p>
                  </div>
                </div>
              </div>

              <!-- Steps -->
              <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:24px;margin-bottom:24px">
                <p style="margin:0 0 16px 0;color:#1f2937;font-size:14px;font-weight:600">Getting started is easy:</p>
                <ol style="margin:0;padding-left:24px;color:#374151;font-size:14px;line-height:1.8;font-weight:400">
                  <li style="margin:8px 0">Open the Passa extension</li>
                  <li style="margin:8px 0">Create a new vault or unlock an existing one</li>
                  <li style="margin:8px 0">When asked, paste your license key above</li>
                  <li style="margin:8px 0">Start using Passa Pro features</li>
                </ol>
              </div>

              <!-- Support -->
              <p style="margin:0;color:#6b7280;font-size:14px;line-height:1.6;font-weight:400">Questions? Our support team is here to help. Reach out to <a href="mailto:support@usepassa.com" style="color:#1f2937;text-decoration:underline;font-weight:600">support@usepassa.com</a>.</p>

              <!-- Footer -->
              <div style="margin-top:40px;padding-top:24px;border-top:1px solid #e5e7eb;text-align:center">
                <p style="margin:0;color:#9ca3af;font-size:12px;font-weight:400">© 2026 Passa. All rights reserved.</p>
              </div>
            </div>
          </div>
        </body>
      </html>
    `,
  });
}
