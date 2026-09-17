FROM node:22-bookworm-slim

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY public ./public
COPY src ./src

RUN mkdir -p /app/data && chown -R node:node /app
USER node

EXPOSE 3000

CMD ["node", "src/server.js"]
