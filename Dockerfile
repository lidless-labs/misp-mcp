FROM node:22-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsup.config.ts ./
COPY src/ src/
RUN npm run build

FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=builder /app/dist/ dist/
# Keep executable code owned by root. Only the runtime home is writable.
RUN chmod -R a-w /app \
    && install -d -o node -g node -m 0700 /run/misp-mcp
ENV NODE_ENV=production
ENV HOME=/run/misp-mcp
USER node:node
ENTRYPOINT ["node", "dist/mcp-bin.js"]
