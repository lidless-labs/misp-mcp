FROM node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsup.config.ts ./
COPY src/ src/
RUN npm run build

FROM node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=builder /app/dist/ dist/
# Keep executable code owned by root. Runtime home and /tmp remain writable.
RUN chmod -R a-w /app \
    && install -d -o node -g node -m 0700 /run/misp-mcp
ENV NODE_ENV=production
ENV HOME=/run/misp-mcp
USER node:node
ENTRYPOINT ["node", "dist/mcp-bin.js"]
