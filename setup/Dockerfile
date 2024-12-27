# acme-id build from rust
FROM rust:1.74 AS rust-builder

WORKDIR /build

RUN apt-get update && apt-get install -y \
    git

RUN git clone https://github.com/marlinprotocol/oyster-caddy-account-uri.git
RUN cd oyster-caddy-account-uri/signer && cargo build --release

# base image
FROM node:22-slim

# install dependency tools
RUN apt-get update && apt-get install -y \
    net-tools \
    iptables \
    iproute2 \
    wget

# working directory
WORKDIR /app

# supervisord to manage programs
RUN wget -O supervisord https://artifacts.marlin.org/oyster/binaries/supervisord_c2cae38b_linux_arm64 && \
    chmod +x supervisord

# transparent proxy component inside the enclave to enable outgoing connections
RUN wget -O ip-to-vsock-transparent https://artifacts.marlin.org/oyster/binaries/ip-to-vsock-transparent_v1.0.0_linux_arm64 && \
    chmod +x ip-to-vsock-transparent

# key generator to generate static keys
RUN wget -O keygen https://artifacts.marlin.org/oyster/binaries/keygen-ed25519_v1.0.0_linux_arm64 && \
    chmod +x keygen

# attestation server inside the enclave that generates attestations
RUN wget -O attestation-server https://artifacts.marlin.org/oyster/binaries/attestation-server_v2.0.0_linux_arm64 && \
    chmod +x attestation-server

# proxy to expose attestation server outside the enclave
RUN wget -O vsock-to-ip https://artifacts.marlin.org/oyster/binaries/vsock-to-ip_v1.0.0_linux_arm64 && \
    chmod +x vsock-to-ip

# dnsproxy to provide DNS services inside the enclave
RUN wget -O dnsproxy https://artifacts.marlin.org/oyster/binaries/dnsproxy_v0.72.0_linux_arm64 && \
    chmod +x dnsproxy

# oyster-keygen for secp256k1
RUN wget -O oyster-keygen https://artifacts.marlin.org/oyster/binaries/keygen-secp256k1_v1.0.0_linux_arm64 && \
    chmod +x oyster-keygen

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
RUN apt-get update -y && apt-get install -y python3 make g++ git && git clone -b main https://github.com/verida/data-connector-server.git && apt-get remove -y git
COPY key.pub /app/keystore/key.pub
COPY secret_manager /app/secret_manager

# copy from rust builder
COPY --from=rust-builder --chown=10005:10005 /build/oyster-caddy-account-uri/signer/target/release/signer /app/acme-id

# entry point
ENTRYPOINT [ "/app/setup.sh" ]
