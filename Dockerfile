FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap python3 python3-pip ca-certificates \
    && pip3 install --break-system-packages --no-cache-dir wapiti3 \
    && pip3 install --break-system-packages --no-cache-dir semgrep==1.179.0 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
ENV NODE_ENV=production
USER node
EXPOSE 8080
CMD ["sh","-c","if [ -n \"$DATABASE_URL\" ]; then npm run db:init; fi && npm start"]
