module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  extends: ['standard-with-typescript'],
  plugins: ['svelte3', '@typescript-eslint'],
  ignorePatterns: ['*.cjs'],
  overrides: [{ files: ['*.svelte'], processor: 'svelte3/svelte3' }],
  settings: {
    'svelte3/typescript': () => require('typescript')
  },
  parserOptions: {
    sourceType: 'module',
    ecmaVersion: 2020,
    project: './tsconfig.json'
  },
  env: {
    browser: true,
    es2017: true,
    node: true
  }
}
