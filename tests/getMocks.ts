// Typed accessor for the global mock objects set up in setup.ts.
// Import this instead of accessing global.__mocks__ directly.

type MockDoc = { exists: boolean; data: () => Record<string, unknown> };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type MockFn = jest.Mock<any>;

export interface Mocks {
  makeDoc: (exists: boolean, data?: Record<string, unknown>) => MockDoc;
  mockDocRef: { get: MockFn; set: MockFn; update: MockFn };
  mockCollectionRef: { doc: MockFn; add: MockFn };
  mockDb: { collection: MockFn; batch: MockFn; runTransaction: MockFn };
  mockBatch: { update: MockFn; set: MockFn; commit: MockFn };
  mockTransaction: { get: MockFn; update: MockFn; set: MockFn };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const getMocks = (): Mocks => (global as any).__mocks__;
