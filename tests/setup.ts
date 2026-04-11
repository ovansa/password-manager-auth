// Environment variables required before any module loads
process.env.FIREBASE_PROJECT_ID = 'test-project';
process.env.FIREBASE_CLIENT_EMAIL = 'test@test-project.iam.gserviceaccount.com';
process.env.FIREBASE_PRIVATE_KEY =
  '-----BEGIN RSA PRIVATE KEY-----\nMIItest\n-----END RSA PRIVATE KEY-----';
process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
process.env.SERVER_URL = 'https://test.example.com';
process.env.NODE_ENV = 'test';

// ── Firebase Admin mock ────────────────────────────────────────────────────
// We mock the entire firebase-admin module so no real Firestore/credentials
// are needed. Tests control document existence and data via jest.fn().

const mockBatch = {
  update: jest.fn().mockReturnThis(),
  set: jest.fn().mockReturnThis(),
  commit: jest.fn().mockResolvedValue(undefined),
};

const mockTransaction = {
  get: jest.fn(),
  update: jest.fn().mockReturnThis(),
  set: jest.fn().mockReturnThis(),
};

// Default document factory - tests override per case via mockResolvedValueOnce
const makeDoc = (exists: boolean, data: Record<string, unknown> = {}) => ({
  exists,
  data: () => data,
});

const mockDocRef = {
  get: jest.fn().mockResolvedValue(makeDoc(false)),
  set: jest.fn().mockResolvedValue(undefined),
  update: jest.fn().mockResolvedValue(undefined),
};

const mockCollectionRef = {
  doc: jest.fn().mockReturnValue(mockDocRef),
  add: jest.fn().mockResolvedValue({ id: 'new-doc-id' }),
};

const mockDb = {
  collection: jest.fn().mockReturnValue(mockCollectionRef),
  batch: jest.fn().mockReturnValue(mockBatch),
  runTransaction: jest
    .fn()
    .mockImplementation(
      async (fn: (tx: typeof mockTransaction) => Promise<unknown>) =>
        fn(mockTransaction),
    ),
};

jest.mock('firebase-admin', () => ({
  initializeApp: jest.fn(),
  credential: { cert: jest.fn().mockReturnValue({}) },
  firestore: Object.assign(jest.fn().mockReturnValue(mockDb), {
    FieldValue: {
      serverTimestamp: jest.fn().mockReturnValue('SERVER_TIMESTAMP'),
      increment: jest.fn((n: number) => ({ _increment: n })),
    },
    Timestamp: {
      fromDate: jest.fn((d: Date) => ({ toDate: () => d })),
    },
  }),
  apps: [],
}));

// ── bcrypt mock ────────────────────────────────────────────────────────────
jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('hashed_value'),
  compare: jest.fn().mockResolvedValue(true),
}));

// ── axios mock ─────────────────────────────────────────────────────────────
jest.mock('axios', () => {
  const axios = jest.fn().mockResolvedValue({ data: {} });
  (axios as unknown as Record<string, unknown>).post = jest
    .fn()
    .mockResolvedValue({
      data: {
        access_token: 'test_access_token',
        refresh_token: 'test_refresh_token',
        expires_in: 3600,
      },
    });
  (axios as unknown as Record<string, unknown>).HttpStatusCode = {
    Created: 201,
  };
  return axios;
});

// Expose helpers for tests to reach into mocks
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(global as any).__mocks__ = {
  makeDoc,
  mockDocRef,
  mockCollectionRef,
  mockDb,
  mockBatch,
  mockTransaction,
};
