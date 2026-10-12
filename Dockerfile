FROM node:22-alpine

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app/

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "serve.js"]
