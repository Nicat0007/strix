# ---------------------------------------------------------------------------
# Builder stage: compile the Go tools here so the Go toolchain (~225MB) and the
# module/build caches never reach the runtime image. The resulting binaries are
# statically linked and copied into the final stage.
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling:latest AS gobuilder

RUN apt-get update && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-go git ca-certificates

ENV GOBIN=/out/bin
# Network-resilient module fetch. The build host's egress to sum.golang.org is flaky
# (intermittent "unexpected EOF" on the checksum-DB tiles) and proxy.golang.org has
# refused connections mid-build; both abort the whole RUN. GOSUMDB=off skips the
# transparency-log verification (modules still come from the proxy), GOPROXY falls back
# to direct VCS when the proxy refuses, and the retry loop rides out transient drops.
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=off
RUN mkdir -p /out/bin && \
    n=0; until [ "$n" -ge 4 ]; do \
      go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
      go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
      go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest && \
      go install -v github.com/jaeles-project/gospider@latest && \
      go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
      go install -v golang.org/x/vuln/cmd/govulncheck@latest && \
      go install -v github.com/lc/gau/v2/cmd/gau@latest && \
      go install -v github.com/tomnomnom/waybackurls@latest && break; \
      n=$((n+1)); echo "go install attempt $n failed; retrying in 15s"; sleep 15; \
    done; \
    test -x /out/bin/httpx && test -x /out/bin/waybackurls

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling:latest

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    software-properties-common \
    gcc libc6-dev \
    python3 python3-pip python3-venv python3-setuptools \
    net-tools dnsutils whois \
    file xxd \
    jq parallel ripgrep grep \
    less procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    apktool jadx dex2jar adb \
    nodejs npm pipx \
    golang-go \
    libcap2-bin \
    gdb \
    libnss3-tools \
    chromium fonts-liberation


RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

USER pentester
RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

USER pentester
WORKDIR /tmp

# Go tools are built in the gobuilder stage; copy the static binaries only.
COPY --from=gobuilder --chown=pentester:pentester /out/bin/ /home/pentester/go/bin/

RUN nuclei -update-templates

RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch 'setuptools<81' && \
    pipx install wafw00f && \
    pipx install frida-tools && \
    pipx install androguard && \
    pipx install objection

# Mobile APK-repackaging toolchain for the NON-ROOTED dynamic path. On a non-rooted
# device (or real phone) `frida-server` + `su` is unavailable, so TLS unpinning +
# traffic capture must come from a REPACKAGED app with an embedded Frida gadget
# (`objection patchapk` / manual gadget injection). apksigner + zipalign re-sign and
# align the rebuilt APK; aapt inspects manifest/badging. Harmless for rooted flows.
# apt needs root; the build switched to USER pentester above, so switch back for this.
USER root
# NOTE: do not `rm -rf /var/lib/apt/lists/*` here — a later bare `apt-get install
# wapiti` (no update of its own) relies on the package lists staying present.
RUN apt-get update && \
    apt-get install -y --no-install-recommends apksigner zipalign aapt
USER pentester

# mobsfscan: the lightweight MobSF static SAST engine (semgrep-based Android/iOS
# security rules) WITHOUT the heavy MobSF Django app — a one-shot static scan over
# the decompiled app source that complements jadx/apktool + the android.md sweep.
RUN pipx install mobsfscan

# Default ADB bridge target: the container's adb client talks to the operator's
# HOST adb server (and thus their Genymotion) via the host-gateway mapping. Only
# used by the mobile (adb/frida) flows; harmless otherwise. The host must expose
# its adb server (`adb -a -P 5037 nodaemon server`); tooling/adb.md re-exports
# this too so it survives the entrypoint UID-remap re-exec.
ENV ADB_SERVER_SOCKET=tcp:host.docker.internal:5037

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest && \
    npm install -g @ast-grep/cli@latest && \
    npm install -g tree-sitter-cli@latest && \
    npm install -g agent-browser@0.26.0 && \
    npm cache clean --force && \
    # ast-grep ships two identical binaries (`ast-grep` and `sg`); dedupe (~52MB)
    ln -sf ast-grep /home/pentester/.npm-global/lib/node_modules/@ast-grep/cli/sg

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
ENV AGENT_BROWSER_IDLE_TIMEOUT_MS=180000
USER root
RUN set -eu; \
    { \
        for var in AGENT_BROWSER_EXECUTABLE_PATH AGENT_BROWSER_USER_AGENT \
                   AGENT_BROWSER_ARGS AGENT_BROWSER_SCREENSHOT_DIR \
                   AGENT_BROWSER_IDLE_TIMEOUT_MS; do \
            eval "value=\${$var}"; \
            printf 'export %s="${%s:-%s}"\n' "$var" "$var" "$value"; \
        done; \
    } > /tmp/agent-browser.sh; \
    install -m 0644 /tmp/agent-browser.sh /etc/profile.d/agent-browser.sh; \
    rm /tmp/agent-browser.sh; \
    env -i bash -lc 'test "${AGENT_BROWSER_IDLE_TIMEOUT_MS}" = "180000"'
USER pentester
RUN /home/pentester/.npm-global/bin/agent-browser doctor --offline --quick

RUN set -eux; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    for repo in tree-sitter-java tree-sitter-javascript tree-sitter-python tree-sitter-go tree-sitter-bash tree-sitter-json tree-sitter-yaml tree-sitter-typescript; do \
        if [ "$repo" = "tree-sitter-yaml" ]; then \
            repo_url="https://github.com/tree-sitter-grammars/${repo}.git"; \
        else \
            repo_url="https://github.com/tree-sitter/${repo}.git"; \
        fi; \
        if [ ! -d "${TS_PARSER_DIR}/${repo}" ]; then \
            git clone --depth 1 "${repo_url}" "${TS_PARSER_DIR}/${repo}"; \
        fi; \
    done; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py && \
    git clone https://github.com/obheda12/GitDorker.git

USER root

# Install trufflehog into a pentester-owned dir on PATH so its runtime self-update
# (which replaces the binary in place) succeeds: as non-root `pentester` it cannot
# overwrite a root-owned binary under /usr/local/bin, which otherwise fails with
# "cannot move binary" and aborts the scan. Pin the initial version for
# reproducible builds; self-update then pulls fresh detectors at runtime.
ARG TRUFFLEHOG_VERSION=3.95.9
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /home/pentester/.local/bin "v${TRUFFLEHOG_VERSION}" && \
    chown -R pentester:pentester /home/pentester/.local
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) GITLEAKS_ARCH="x64" ;; \
        aarch64|arm64) GITLEAKS_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    TAG="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)"; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${TAG}/gitleaks_${TAG#v}_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/gitleaks.tgz; \
    tar -xzf /tmp/gitleaks.tgz -C /tmp; \
    install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks; \
    rm -f /tmp/gitleaks /tmp/gitleaks.tgz

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN apt-get install -y wapiti

# x8 — fast hidden-parameter discovery (response-diff based). Deepens the param
# surface where ~70% of IDOR/XSS/SQLi hide; complements arjun in recon. Single
# gzipped Linux binary from GitHub releases (latest-by-name redirect, no version pin).
RUN curl -fsSL "https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8.gz" -o /tmp/x8.gz && \
    gzip -d /tmp/x8.gz && \
    install -m 0755 /tmp/x8 /usr/local/bin/x8 && \
    rm -f /tmp/x8.gz /tmp/x8

USER pentester

RUN pipx install semgrep && \
    pipx install bandit

RUN npm install -g jshint

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # Purge non-English locales (~160MB)
    find /usr/share/locale -mindepth 1 -maxdepth 1 -type d \
        ! -name 'en' ! -name 'en_US' ! -name 'C' -exec rm -rf {} + && \
    # Remove package documentation and man pages not needed at runtime (~95MB)
    rm -rf /usr/share/doc/* /usr/share/doc-base/* /usr/share/man/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

ARG CAIDO_VERSION=0.56.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

USER pentester
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir caido-sdk-client && \
    /app/.venv/bin/pip install --no-cache-dir \
        requests httpx beautifulsoup4 lxml pyjwt cryptography && \
    /app/.venv/bin/pip install --no-cache-dir -r /home/pentester/tools/jwt_tool/requirements.txt && \
    /app/.venv/bin/pip install --no-cache-dir -r /home/pentester/tools/GitDorker/requirements.txt && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool && \
    printf '%s\n' \
        '#!/bin/bash' \
        '# GitDorker requires a GitHub PAT via -tf <tokenfile>. If the caller' \
        '# did not pass -tf explicitly, materialize one from $GITHUB_TOKEN so' \
        '# the caller only has to set the env var. Never bake a token into the image.' \
        'set -e' \
        'tokenfile=""' \
        'cleanup() { [ -n "$tokenfile" ] && rm -f "$tokenfile"; }' \
        'trap cleanup EXIT' \
        'if [ -n "$GITHUB_TOKEN" ] && ! printf "%s\n" "$@" | grep -q -- "-tf"; then' \
        '    tokenfile="$(mktemp)"' \
        '    printf "%s\n" "$GITHUB_TOKEN" > "$tokenfile"' \
        '    set -- "$@" -tf "$tokenfile"' \
        'fi' \
        'exec /app/.venv/bin/python /home/pentester/tools/GitDorker/GitDorker.py "$@"' \
        > /home/pentester/.local/bin/gitdorker && \
    chmod +x /home/pentester/.local/bin/gitdorker

COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/opt/strix-python

# Project-authored, high-precision semgrep/gitleaks rules that
# custom/source_aware_sast.md's baseline bundle layers on top of the
# public p/default+p/golang+p/secrets packs and gitleaks' own default
# ruleset. See strix/skills/custom/semgrep-rules/ and
# strix/skills/custom/gitleaks-rules/ for what each rule does and why.
COPY --chown=pentester:pentester strix/skills/custom/semgrep-rules /home/pentester/tools/semgrep-rules
COPY --chown=pentester:pentester strix/skills/custom/gitleaks-rules /home/pentester/tools/gitleaks-rules

# Login shells (e.g. `bash -lc`) source /etc/profile, which on Debian/Kali
# hard-resets PATH and drops the image's ENV PATH entries. Re-add the same
# directories here — including /app/.venv/bin — so `python3`/`pip` resolve to
# the venv (which ships requests, httpx, bs4, lxml, pyjwt, cryptography, and the
# Caido SDK) instead of the externally-managed system interpreter.
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
