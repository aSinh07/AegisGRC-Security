FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap tshark sqlmap python3 python3-pip python3-venv ca-certificates curl unzip \
    && python3 -m venv /opt/wapiti && /opt/wapiti/bin/pip install --no-cache-dir wapiti3==3.2.3 \
    && ln -s /opt/wapiti/bin/wapiti /usr/local/bin/wapiti \
    && python3 -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.179.0 \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && NUCLEI_VERSION=3.4.10 && curl -fsSL -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin && chmod 0755 /usr/local/bin/nuclei && rm /tmp/nuclei.zip \
    && TRIVY_VERSION=0.74.0 && curl -fsSL -o /tmp/trivy.deb https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb \
    && dpkg -i /tmp/trivy.deb && rm /tmp/trivy.deb \
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
