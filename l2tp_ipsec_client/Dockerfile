# Build from a fixed upstream release commit, not the moving main branch.
FROM golang:1.27.0-alpine AS engine-build
ARG VEEPIN_COMMIT=6c37e3691c326e54956cea042e2df67d3717e7a4
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN apk add --no-cache git ca-certificates
WORKDIR /src
RUN git init . \
    && git remote add origin https://github.com/xen0bit/veepin.git \
    && git fetch --depth=1 origin "${VEEPIN_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${VEEPIN_COMMIT}"
# We use only the L2TP library, not the upstream CLI or its default routing.
COPY helper/ /src/cmd/ha-c6vpn/
RUN go mod download \
    && go test ./cmd/ha-c6vpn \
    && go build -trimpath -buildvcs=false -ldflags='-s -w' \
         -o /out/c6-vpn-engine ./cmd/ha-c6vpn \
    && /out/c6-vpn-engine --version

FROM alpine:3.23
ARG BUILD_VERSION=0.2.0
ARG BUILD_ARCH=amd64
RUN apk add --no-cache python3 iproute2 tini tzdata \
    && mkdir -p /app /usr/share/licenses/veepin
COPY --from=engine-build /out/c6-vpn-engine /usr/local/bin/c6-vpn-engine
COPY --from=engine-build /src/LICENSE /usr/share/licenses/veepin/LICENSE
COPY main.py /app/main.py
RUN python3 -m py_compile /app/main.py \
    && /usr/local/bin/c6-vpn-engine --version \
    && command -v ip
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
LABEL io.hass.name="L2TP/IPsec Client - C6 gateway" \
      io.hass.description="Experimental userspace-PPP VPN and C6 proxy" \
      io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"
ENTRYPOINT ["/sbin/tini", "--", "python3", "/app/main.py"]
