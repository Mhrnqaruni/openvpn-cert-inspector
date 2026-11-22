# Lab image: OpenVPN 2.6 from Debian, optionally the OpenVPN 3 core test client.
#
#   docker build -t ovpncert-lab lab/
#   docker build -t ovpncert-lab --build-arg OPENVPN3=1 lab/      # also build OpenVPN 3
#   docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
#       -v "$PWD:/src" ovpncert-lab python3 /src/lab/run_lab.py --out /src/results

FROM debian:trixie-slim AS openvpn3
ARG OPENVPN3=0
ARG OPENVPN3_REF=release/3.11.3
RUN if [ "$OPENVPN3" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates pkg-config libasio-dev liblz4-dev \
        libssl-dev libxxhash-dev libcap-dev \
      && git clone --depth 1 --branch "$OPENVPN3_REF" https://github.com/OpenVPN/openvpn3.git /openvpn3 \
      && cmake -S /openvpn3 -B /openvpn3/build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
      && cmake --build /openvpn3/build --target ovpncli -j"$(nproc)" \
      && cp "$(find /openvpn3/build -name ovpncli -type f -perm -u+x | head -n1)" /usr/local/bin/ovpncli; \
    else touch /usr/local/bin/.no-openvpn3; fi

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openvpn python3 python3-cryptography iproute2 ca-certificates liblz4-1 libcap2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=openvpn3 /usr/local/bin/ /usr/local/bin/
WORKDIR /src
