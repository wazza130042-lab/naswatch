FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
      libtalloc2 libsctp1 libgnutls30 libtins4.5 libpcap0.8 libyaml-0-2 \
      libmicrohttpd12 libdbus-1-3 libsystemd0 iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV LD_LIBRARY_PATH=/opt/open5gs/lib/x86_64-linux-gnu
ENTRYPOINT ["/opt/open5gs/bin/open5gs-upfd"]
