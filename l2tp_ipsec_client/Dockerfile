FROM alpine:3.23

ARG BUILD_VERSION=0.1.0
ARG BUILD_ARCH=amd64

RUN apk add --no-cache \
      strongswan xl2tpd ppp-daemon ppp-l2tp \
      iproute2 iptables kmod python3 tini \
    && mkdir -p /app /run/xl2tpd /etc/ppp /etc/xl2tpd

COPY main.py /app/main.py

RUN python3 -m py_compile /app/main.py \
    && command -v ipsec && command -v xl2tpd && command -v pppd \
    && command -v ip && command -v iptables && command -v modprobe

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
LABEL io.hass.name="L2TP/IPsec Client - C6 gateway" \
      io.hass.description="Experimental L2TP/IPsec client with an internal C6 TCP proxy" \
      io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"

ENTRYPOINT ["/sbin/tini", "--", "python3", "/app/main.py"]
