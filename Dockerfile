FROM node:20-alpine

WORKDIR /app

# Drop root — run as non-root user
RUN addgroup -S gktester && adduser -S gktester -G gktester

# Install dependencies first (better layer caching)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY public/ ./public/

USER gktester

# HTTP UI + API
EXPOSE 3000
# HTTPS capture webhook (receives real AdmissionReview from kube-apiserver)
EXPOSE 8443

ENV NODE_ENV=production

CMD ["node", "server.js"]
