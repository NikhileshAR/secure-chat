FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY deploy ./deploy
EXPOSE 8080
ENV RELAY_PORT=8080
ENV MAX_CONNECTIONS=1000
ENV EPHEMERAL_MODE=true
ENV LOG_LEVEL=minimal
ENV ENABLE_METRICS=true
CMD ["sh", "-c", "cp -n deploy/relay.config.example.json relay.config.json && node deploy/start-relay.js --config relay.config.json"]
