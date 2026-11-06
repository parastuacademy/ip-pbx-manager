# ip-pbx-manager — image with multiple roles (asterisk / panel / all)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Tehran

# Asterisk (call engine) + Python (panel) + supervisor (for the "all" role)
# NOTE: if pip/apt are slow in your region you can pass a mirror:
#   docker build --build-arg APT_MIRROR=... ; or set PIP_INDEX_URL as build-arg below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        asterisk \
        python3 \
        python3-pip \
        supervisor \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ipbx

COPY app/requirements.txt /opt/ipbx/app/requirements.txt
RUN pip3 install --no-cache-dir -r /opt/ipbx/app/requirements.txt

COPY app/ /opt/ipbx/app/
COPY asterisk/ /etc/asterisk/
COPY manager.conf.template /opt/ipbx/manager.conf.template
COPY entrypoint.sh /opt/ipbx/entrypoint.sh
COPY supervisord-all.conf /opt/ipbx/supervisord-all.conf

RUN chmod +x /opt/ipbx/entrypoint.sh \
    && mkdir -p /data/asterisk /data/cdr /data/recordings /data/astdb /data/log /data/spool

ENV PBX_ROLE=all \
    AMI_HOST=localhost \
    AMI_PASSWORD=ipbx-ami-change-me \
    PANEL_PORT=8080 \
    IPBX_DATA_DIR=/data

EXPOSE 5060/udp 10000-10100/udp 8080/tcp

ENTRYPOINT ["/opt/ipbx/entrypoint.sh"]
