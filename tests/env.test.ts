import { validateStartupEnv } from '../src/config/env';

describe('validateStartupEnv', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.restoreAllMocks();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  test('fails fast in production when email delivery keys are missing', () => {
    process.env.NODE_ENV = 'production';
    process.env.FIREBASE_PROJECT_ID = 'test-project';
    process.env.FIREBASE_CLIENT_EMAIL = 'test@test-project.iam.gserviceaccount.com';
    process.env.FIREBASE_PRIVATE_KEY = 'test-private-key';
    process.env.SERVER_URL = 'https://api.example.com';
    process.env.GOOGLE_CLIENT_ID = 'google-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'google-client-secret';
    process.env.FRONTEND_URL = 'https://app.example.com';
    process.env.LICENSE_SIGNING_PRIVATE_KEY = 'test-license-private-key';
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = 'test-lemon-secret';
    process.env.LEMON_VARIANT_LIFETIME_ID = 'lifetime-variant';
    delete process.env.RESEND_API_KEY;
    delete process.env.TRANSACTIONAL_EMAIL_FROM;

    const exitSpy = jest
      .spyOn(process, 'exit')
      .mockImplementation((() => undefined) as never);

    validateStartupEnv();

    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});
