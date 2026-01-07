FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache python3 make g++ openssl

COPY package*.json ./

RUN npm install --omit=dev

COPY . .

RUN chmod +x entrypoint.sh

EXPOSE 3000

CMD ["./entrypoint.sh"]