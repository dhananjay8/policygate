/** Root Jest config: `unit` runs package unit tests, `e2e` runs HTTP integration tests. */
module.exports = {
  projects: [
    {
      displayName: 'unit',
      testEnvironment: 'node',
      transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: '<rootDir>/packages/policygate/tsconfig.json' }] },
      testMatch: ['<rootDir>/packages/policygate/test/**/*.spec.ts'],
    },
    {
      displayName: 'e2e',
      testEnvironment: 'node',
      // Scope the haste map to the app: the workspace package is then only
      // seen via the node_modules symlink -> dist (tests the real built
      // artifact) instead of colliding as two same-name packages.
      roots: ['<rootDir>/apps/demo-billing-service'],
      transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: '<rootDir>/apps/demo-billing-service/tsconfig.json' }] },
      testMatch: ['<rootDir>/apps/demo-billing-service/test/**/*.e2e-spec.ts'],
    },
  ],
};
