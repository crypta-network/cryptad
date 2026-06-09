FROM docker.io/benyamin/codex-sandbox:latest

ARG GITHUB_MCP_VERSION
ARG GITHUB_MCP_ARCH=arm64
ARG ACTIONLINT_VERSION
ARG ACTIONLINT_ARCH=arm64
ARG PLAYWRIGHT_VERSION=1.60.0
ARG NCURSES_VERSION=6.6
ARG NCURSES_SHA256=355b4cbbed880b0381a04c46617b7656e362585d52e9cf84a67e2009b749ff11
ARG CODEX_SSH_AUTHORIZED_KEYS=""

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    VISUAL=nvim \
    PLAYWRIGHT_REMOTE_WS_ENDPOINT=ws://playwright:3000/ \
    PW_TEST_CONNECT_WS_ENDPOINT=ws://playwright:3000/ \
    UV_INSTALL_DIR=/usr/local/bin \
    UV_NO_MODIFY_PATH=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN set -eux; \
    mkdir -p -m 755 /etc/apt/keyrings /etc/apt/sources.list.d; \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install -y --no-install-recommends \
      bubblewrap \
      build-essential \
      libharfbuzz0b \
      libfontconfig1 \
      libfreetype6 \
      fonts-dejavu-core \
      openjdk-25-jdk-headless \
      wget \
      openssh-client \
      openssh-server \
      file \
      yq \
      fd-find \
      gh \
      binutils \
      fakeroot \
      tmux \
      neovim; \
    ln -sf /usr/bin/fdfind /usr/local/bin/fd; \
    npm install --global @ast-grep/cli; \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --global "playwright@${PLAYWRIGHT_VERSION}"; \
    cd /tmp; \
    curl -fsSL -o github-mcp-server.tar.gz \
      "https://github.com/github/github-mcp-server/releases/download/${GITHUB_MCP_VERSION}/github-mcp-server_Linux_${GITHUB_MCP_ARCH}.tar.gz"; \
    tar xzf github-mcp-server.tar.gz; \
    install -m 0755 github-mcp-server /usr/local/bin/github-mcp-server; \
    rm -f github-mcp-server.tar.gz github-mcp-server; \
    ACTIONLINT_ARCHIVE="actionlint_${ACTIONLINT_VERSION}_linux_${ACTIONLINT_ARCH}.tar.gz"; \
    curl -fsSL -o "${ACTIONLINT_ARCHIVE}" \
      "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/${ACTIONLINT_ARCHIVE}"; \
    curl -fsSL -o actionlint_checksums.txt \
      "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_checksums.txt"; \
    grep "  ${ACTIONLINT_ARCHIVE}$" actionlint_checksums.txt | sha256sum -c -; \
    tar xzf "${ACTIONLINT_ARCHIVE}" actionlint; \
    install -m 0755 actionlint /usr/local/bin/actionlint; \
    rm -f "${ACTIONLINT_ARCHIVE}" actionlint_checksums.txt actionlint; \
    curl -LsSf https://astral.sh/uv/install.sh | sh; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN set -eux; \
    cd /tmp; \
    curl -fsSL -o ncurses.tar.gz \
      "https://ftp.gnu.org/pub/gnu/ncurses/ncurses-${NCURSES_VERSION}.tar.gz"; \
    printf '%s  %s\n' "${NCURSES_SHA256}" ncurses.tar.gz | sha256sum -c -; \
    tar xzf ncurses.tar.gz; \
    cd "ncurses-${NCURSES_VERSION}"; \
    ./configure \
      --prefix=/usr/local \
      --without-ada \
      --without-cxx-binding \
      --without-debug \
      --without-manpages \
      --without-shared \
      --without-tests; \
    make -j"$(nproc)"; \
    make install.progs install.data; \
    tic -x -o /usr/local/share/terminfo misc/terminfo.src; \
    infocmp -x -A /usr/local/share/terminfo ghostty \
      | awk 'BEGIN { done = 0 } !done && /^ghostty[|,]/ { sub(/^ghostty[|,]/, "xterm-ghostty|"); done = 1 } { print }' \
      | tic -x -o /usr/local/share/terminfo -; \
    mkdir -p /usr/share/terminfo/g /usr/share/terminfo/x; \
    cp /usr/local/share/terminfo/g/ghostty /usr/share/terminfo/g/ghostty; \
    cp /usr/local/share/terminfo/x/xterm-ghostty /usr/share/terminfo/x/xterm-ghostty; \
    infocmp -A /usr/share/terminfo ghostty >/dev/null; \
    infocmp -A /usr/share/terminfo xterm-ghostty >/dev/null; \
    rm -rf /tmp/*

RUN set -eux; \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --global --force "@playwright/test@${PLAYWRIGHT_VERSION}"

RUN set -eux; \
    if [ -f /usr/local/bin/zai-codex-entrypoint ]; then \
      sed -i \
        -e 's/^ClientAliveInterval 60$/ClientAliveInterval 0/' \
        -e 's/^ClientAliveCountMax 3$/ClientAliveCountMax 0/' \
        /usr/local/bin/zai-codex-entrypoint; \
    fi; \
    mkdir -p /etc/ssh/authorized_keys /etc/ssh/sshd_config.d /run/sshd; \
    printf '%s\n' \
      'PermitRootLogin prohibit-password' \
      'PasswordAuthentication no' \
      'KbdInteractiveAuthentication no' \
      'PubkeyAuthentication yes' \
      'AuthorizedKeysFile /etc/ssh/authorized_keys/%u .ssh/authorized_keys' \
      'ClientAliveInterval 0' \
      'ClientAliveCountMax 0' \
      > /etc/ssh/sshd_config.d/99-codex.conf; \
    if [ -n "${CODEX_SSH_AUTHORIZED_KEYS}" ]; then \
      printf '%s\n' "${CODEX_SSH_AUTHORIZED_KEYS}" > /etc/ssh/authorized_keys/root; \
    else \
      touch /etc/ssh/authorized_keys/root; \
    fi; \
    chmod 0755 /etc/ssh/authorized_keys /run/sshd; \
    chmod 0644 /etc/ssh/authorized_keys/root; \
    ssh-keygen -A; \
    sshd -t

WORKDIR /work

COPY tmux.conf /etc/tmux.conf
COPY playwright-remote /usr/local/bin/playwright-remote
COPY start-codex-remote-control-daemon.sh /usr/local/bin/start-codex-remote-control-daemon
RUN chmod 0755 \
    /usr/local/bin/playwright-remote \
    /usr/local/bin/start-codex-remote-control-daemon

EXPOSE 22

CMD ["start-codex-remote-control-daemon"]
