export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // @noble/ed25519 ships ESM-only, so the default node_modules transform
  // exclusion is lifted for it and ts-jest transpiles it to CommonJS. All
  // other node_modules packages stay untransformed.
  transform: {
    '^.+\\.tsx?$': ['ts-jest'],
    'node_modules/@noble/ed25519/.+\\.m?js$': [
      'ts-jest',
      { tsconfig: { allowJs: true, target: 'ES2020', module: 'commonjs', esModuleInterop: true } },
    ],
  },
  transformIgnorePatterns: ['/node_modules/(?!@noble/ed25519/)'],
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
