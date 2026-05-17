import typescript from 'rollup-plugin-typescript2';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'src/index.ts',
  output: [
    {
      file: 'dist/index.mjs',
      format: 'es',
      sourcemap: true
    },
    {
      file: 'dist/index.cjs',
      format: 'cjs',
      sourcemap: true
    }
  ],
  plugins: [
    resolve({
      preferBuiltins: true,
      browser: false
    }),
    commonjs(),
    typescript({
      tsconfig: './tsconfig.json',
      useTsconfigDeclarationDir: false
    })
  ],
  // socket.io-client is a heavy runtime dependency; leave it to the consumer to provide.
  // @noble/* ship as ESM with TypeScript sources alongside index.js; mark them external
  // so rpt2 doesn't try to re-compile their .ts files (which trip strict mode against
  // ArrayBufferLike). Consumers resolve them via their own node_modules.
  external: [
    'socket.io-client',
    '@noble/ed25519',
    '@noble/hashes/sha512',
    '@noble/hashes/sha256',
    '@noble/hashes/hmac',
  ]
};
