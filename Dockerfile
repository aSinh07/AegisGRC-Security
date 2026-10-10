FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap tshark sqlmap python3 python3-pip ca-certificates curl unzip \
    && pip3 install --break-system-packages --no-cache-dir wapiti3 \
    && pip3 install --break-system-packages --no-cache-dir "httpx==0.27.2" \
    && pip3 install --break-system-packages --no-cache-dir semgrep==1.179.0 \
    && NUCLEI_VERSION=3.4.10 && curl -fsSL -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin && chmod 0755 /usr/local/bin/nuclei && rm /tmp/nuclei.zip \
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
