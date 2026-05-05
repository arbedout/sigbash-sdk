# syntax=docker/dockerfile:1
FROM node:22-alpine
WORKDIR /app

RUN cat > package.json << 'EOF'
{
  "name": "sigbash-http-server",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@sigbash/sdk": "^0.1.0",
    "express": "^4"
  }
}
EOF

RUN npm install

COPY server.js .

EXPOSE 3000

# Required: SIGBASH_SERVER_URL, SIGBASH_API_KEY, SIGBASH_USER_KEY, SIGBASH_SECRET_KEY
# Optional: SIGBASH_WASM_URL (default: https://www.sigbash.com/sigbash.wasm), PORT (default: 3000)
CMD ["node", "server.js"]
