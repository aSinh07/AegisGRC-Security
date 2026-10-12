FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap tshark sqlmap python3 python3-pip python3-venv ca-certificates curl unzip git openssl lynis \
    && python3 -m venv /opt/wapiti && /opt/wapiti/bin/pip install --no-cache-dir wapiti3==3.2.3 && /opt/wapiti/bin/pip install --no-cache-dir --upgrade h11==0.16.0 \
    && ln -s /opt/wapiti/bin/wapiti /usr/local/bin/wapiti \
    && python3 -m venv /opt/checkov && /opt/checkov/bin/pip install --no-cache-dir checkov==3.2.490 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
    && TESTSSL_VERSION=3.2.2 && curl -fsSL -o /tmp/testssl.tar.gz https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz && tar -xzf /tmp/testssl.tar.gz -C /opt && ln -s /opt/testssl.sh-${TESTSSL_VERSION}/testssl.sh /usr/local/bin/testssl.sh && rm /tmp/testssl.tar.gz \
    && GRYPE_VERSION=0.120.1 && for i in 1 2 3; do curl --retry 3 --retry-all-errors --connect-timeout 15 -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v${GRYPE_VERSION} && break; test $i -eq 3 && exit 1; sleep 5; done \
    && SYFT_VERSION=1.54.1 && for i in 1 2 3; do curl --retry 3 --retry-all-errors --connect-timeout 15 -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v${SYFT_VERSION} && break; test $i -eq 3 && exit 1; sleep 5; done \ \
    && KUBESCAPE_VERSION=4.0.15 && curl --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 15 -fsSL -o /usr/local/bin/kubescape https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_amd64 && chmod 0755 /usr/local/bin/kubescape \
    && python3 -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.179.0 \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && NUCLEI_VERSION=3.11.1 && curl --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 15 -fsSL -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin && chmod 0755 /usr/local/bin/nuclei && rm /tmp/nuclei.zip \
    && TRIVY_VERSION=0.75.0 && curl --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 15 -fsSL -o /tmp/trivy.deb https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb \
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
