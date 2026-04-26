FROM node:20-alpine AS base
WORKDIR /app
RUN apk add --no-cache curl

FROM base AS deps
COPY package*.json ./
RUN npm ci --omit=dev

FROM base AS runtime
COPY --from=deps /app/node_modules ./node_modules
COPY src ./src
COPY package.json ./

USER node
EXPOSE 8080
CMD ["node", "--experimental-vm-modules", "src/index.js"]
