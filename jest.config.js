const ESM_TRANSFORM = [
  'ts-jest',
  { tsconfig: { allowJs: true, target: 'ES2020', module: 'commonjs', esModuleInterop: true } },
];

export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // @noble/ed25519, @noble/curves, and @scure/base ship ESM-only, so the
  // default node_modules transform exclusion is lifted for them and ts-jest
  // transpiles them to CommonJS. All other node_modules packages stay
  // untransformed.
  transform: {
    '^.+\\.tsx?$': ['ts-jest'],
    'node_modules/@noble/ed25519/.+\\.m?js$': ESM_TRANSFORM,
    'node_modules/@noble/curves/.+\\.m?js$': ESM_TRANSFORM,
    'node_modules/@noble/hashes/.+\\.m?js$': ESM_TRANSFORM,
    'node_modules/@scure/base/.+\\.m?js$': ESM_TRANSFORM,
    'node_modules/@scure/bip32/.+\\.m?js$': ESM_TRANSFORM,
  },
  transformIgnorePatterns: [
    '/node_modules/(?!@noble/ed25519/|@noble/curves/|@noble/hashes/|@scure/base/|@scure/bip32/)',
  ],
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  testPathIgnorePatterns: [
    '/node_modules/',
    '<rootDir>/src/__tests__/helpers/',
  ],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.test.ts',
    '!src/**/__tests__/**/*.ts',
    '!src/**/*.d.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};
