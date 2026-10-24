FROM node:25-slim
WORKDIR /opt/argos
# Only this trusted manifest is installed. No customer install/build scripts run.
COPY sandbox/package.json sandbox/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
RUN node_modules/.bin/esbuild src/sandbox/prepare.ts --bundle --platform=node --format=esm --packages=external --outfile=prepare.mjs
COPY sandbox/start-app.mjs ./start-app.mjs
ENV NODE_ENV=production
USER 1000:1000
CMD ["node", "/opt/argos/start-app.mjs"]
