# Runs the Lintsure MCP server over stdio, for directories that start servers in a container (such as Glama).
# It checks the code mounted at /workspace and never sends it anywhere.
FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages ./packages
RUN npm ci && npm run build && npm prune --omit=dev
WORKDIR /workspace
ENTRYPOINT ["node", "/app/packages/mcp/dist/src/index.js"]
