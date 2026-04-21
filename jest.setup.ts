// Override console.log to write content directly to stdout, bypassing
// Jest's "console.log\n  <message>\n  at <stack>" reformatting.
// This keeps WASM trace messages readable without the surrounding noise.
console.log = (...args: unknown[]): void => {
  process.stdout.write(args.map(a => String(a)).join(' ') + '\n');
};
