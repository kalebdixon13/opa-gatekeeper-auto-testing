FROM node:20-alpine

WORKDIR /app

# Drop root — run as non-root user
RUN addgroup -S gktester && adduser -S gktester -G gktester

COPY server.js ./
COPY public/ ./public/

USER gktester

EXPOSE 3000

ENV NODE_ENV=production

CMD ["node", "server.js"]