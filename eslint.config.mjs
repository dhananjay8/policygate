// @ts-check
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/generated/**', 'coverage/**'],
  },
  ...tseslint.configs.recommended,
  eslintConfigPrettier,
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
      'no-console': 'warn',
    },
  },
  {
    // entrypoints and scripts may log to stdout
    files: ['**/main.ts', 'benchmarks/**', 'prisma/seed.ts'],
    rules: { 'no-console': 'off' },
  },
);
