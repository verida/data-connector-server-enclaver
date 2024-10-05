# acme-id build from rust
FROM rust:alpine3.20 AS rust-builder

WORKDIR /build

RUN apk add git alpine-sdk linux-headers
RUN git clone https://github.com/marlinprotocol/oyster-caddy-account-uri.git
RUN cd oyster-caddy-account-uri/signer && cargo build --release

# base image
FROM alpine:3.20

# install dependency tools
RUN apk add --no-cache net-tools iptables iproute2 wget

# working directory
WORKDIR /app

# supervisord to manage programs
RUN wget -O supervisord http://public.artifacts.marlin.pro/projects/enclaves/supervisord_master_linux_arm64
RUN chmod +x supervisord

# transparent proxy component inside the enclave to enable outgoing connections
RUN wget -O ip-to-vsock-transparent http://public.artifacts.marlin.pro/projects/enclaves/ip-to-vsock-transparent_v1.0.0_linux_arm64
RUN chmod +x ip-to-vsock-transparent

# key generator to generate static keys
RUN wget -O keygen http://public.artifacts.marlin.pro/projects/enclaves/keygen_v1.0.0_linux_arm64
RUN chmod +x keygen

# attestation server inside the enclave that generates attestations
RUN wget -O attestation-server http://public.artifacts.marlin.pro/projects/enclaves/attestation-server_v1.0.0_linux_arm64
RUN chmod +x attestation-server

# proxy to expose attestation server outside the enclave
RUN wget -O vsock-to-ip http://public.artifacts.marlin.pro/projects/enclaves/vsock-to-ip_v1.0.0_linux_arm64
RUN chmod +x vsock-to-ip

# dnsproxy to provide DNS services inside the enclave
RUN wget -O dnsproxy http://public.artifacts.marlin.pro/projects/enclaves/dnsproxy_v0.46.5_linux_arm64
RUN chmod +x dnsproxy

RUN wget -O oyster-keygen http://public.artifacts.marlin.pro/projects/enclaves/keygen-secp256k1_v1.0.0_linux_arm64
RUN chmod +x oyster-keygen

# supervisord config
COPY supervisord.conf /etc/supervisord.conf

# setup.sh script that will act as entrypoint
COPY setup.sh ./
RUN chmod +x setup.sh

# setup caddy with namecheap plugin
RUN wget -O caddy "https://caddyserver.com/api/download?os=linux&arch=arm64"
RUN mv caddy /usr/bin/caddy
RUN chmod +x /usr/bin/caddy
ENV XDG_DATA_HOME=/var/lib
COPY Caddyfile /etc/caddy/Caddyfile

# your custom setup goes here
RUN apk add git make gcc g++ npm nodejs yarn iptables-legacy python3
RUN git clone -b release/alpha https://github.com/verida/data-connector-server.git
COPY key.pub /app/keystore/key.pub
COPY secret_manager /app/secret_manager

# Telegram API requires glibc
ENV GLIBC_VERSION=2.35-r1
# Download and install the glibc package
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-${GLIBC_VERSION}.apk && \
    apk add --no-cache glibc-${GLIBC_VERSION}.apk && \
    rm -f glibc-${GLIBC_VERSION}.apk
# Clean up
RUN rm -rf /var/cache/apk/* /tmp/*

# copy from builders
COPY --from=rust-builder --chown=10005:10005 /build/oyster-caddy-account-uri/signer/target/release/signer /app/acme-id

# entry point
ENTRYPOINT [ "/app/setup.sh" ]