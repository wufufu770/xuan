FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

WORKDIR /opt/ARL

# 运行期系统依赖：nmap（端口扫描）、curl（healthcheck）；
# build-essential：mmh3==3.0.0 等旧包无 cp312 轮子，需源码编译；
# xvfb/x11vnc/novnc/websockify + chrome 运行库：会话池窗口登录网关（M3）。
# apt 切换清华镜像（debian 官方源在本网络环境下极慢）
RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
    curl nmap ca-certificates build-essential unzip \
    xvfb x11vnc novnc websockify \
    libglib2.0-0 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    libx11-6 libxcb1 libxext6 libexpat1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt

# NPoC（xing 包）与生产 install.sh 同语义：editable 安装
COPY ARL-NPoC /opt/ARL-NPoC
RUN pip install --no-cache-dir --no-deps -e /opt/ARL-NPoC

COPY app ./app
COPY arl_tool ./arl_tool
COPY tools ./tools

# 扫描器二进制（dev_up.sh 从发行包 payload/bin 阶段到上下文 bin/）
COPY bin /usr/local/bin-staged

# Chrome for Testing：构建上下文未带 tools/chrome-for-testing 时（新 clone）自举下载
RUN if [ ! -x /opt/ARL/tools/chrome-for-testing/151.0.7922.34/chrome-linux64/chrome ]; then \
      curl -fL --retry 3 -o /tmp/chrome.zip \
        https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.34/linux64/chrome-linux64.zip \
      && mkdir -p /opt/ARL/tools/chrome-for-testing/151.0.7922.34 \
      && unzip -q /tmp/chrome.zip -d /opt/ARL/tools/chrome-for-testing/151.0.7922.34 \
      && chmod +x /opt/ARL/tools/chrome-for-testing/151.0.7922.34/chrome-linux64/chrome \
      && rm -f /tmp/chrome.zip; \
    fi
# phantomjs（git 内为 .gz——原始二进制 67MB 超 REST 限制），构建期解压
RUN if [ ! -x /opt/ARL/app/tools/phantomjs ] && [ -f /opt/ARL/app/tools/phantomjs.gz ]; then \
      gunzip -k /opt/ARL/app/tools/phantomjs.gz \
      && chmod +x /opt/ARL/app/tools/phantomjs; \
    fi
RUN find /usr/local/bin-staged -maxdepth 1 -type f \
      -exec install -m 0755 {} /usr/local/bin/ \; \
    && rm -rf /usr/local/bin-staged \
    && chmod +x /opt/ARL/tools/hostcollision-engine \
    && chmod +x /opt/ARL/app/tools/massdns

# 运行期配置由 compose 以卷挂载覆盖（dev-config.yaml）
COPY app/config.yaml.template app/config.yaml

COPY entrypoint.sh /opt/ARL/entrypoint.sh
RUN chmod +x /opt/ARL/entrypoint.sh

EXPOSE 5013
ENTRYPOINT ["/opt/ARL/entrypoint.sh"]
