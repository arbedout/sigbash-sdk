# syntax=docker/dockerfile:1
FROM node:22-alpine
WORKDIR /app

RUN cat > package.json << 'EOF'
{
  "name": "sigbash-http-server",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@sigbash/sdk": "latest",
    "express": "^4"
  }
}
EOF

RUN npm install

COPY server.js .

EXPOSE 3000

# server.js binds 127.0.0.1 by default, which the -p port mapping below can't
# reach — the container needs the wider bind. The listener token (printed to
# stderr on first start, or set explicitly below) is what actually gates
# access once the port is published; -p must never be combined with a skipped
# or leaked token.
ENV SIGBASH_BIND_HOST=0.0.0.0

# Required: SIGBASH_SERVER_URL, SIGBASH_API_KEY, SIGBASH_USER_KEY, SIGBASH_SECRET_KEY
# Optional: SIGBASH_WASM_URL (default: https://www.sigbash.com/sigbash.wasm), PORT (default: 3000),
#           SIGBASH_LISTENER_TOKEN (default: random, printed to stderr on startup)
CMD ["node", "server.js"]
