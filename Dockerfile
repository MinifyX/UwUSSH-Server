# Two stages: build with the full toolchain, ship with none of it.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# `--locked` so the image is built from the versions in Cargo.lock and not
# from whatever was published this morning.
RUN cargo build --release --locked

FROM debian:bookworm-slim
# The server talks to nobody, opens one port and writes one directory, so it
# needs neither certificates nor a shell's worth of packages. It also does not
# need root.
RUN useradd --system --uid 10001 uwussh && mkdir -p /data && chown uwussh /data
COPY --from=build /src/target/release/uwussh-server /usr/local/bin/uwussh-server
USER uwussh
ENV UWUSSH_DATA=/data \
    UWUSSH_LISTEN=0.0.0.0:8443
EXPOSE 8443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/uwussh-server"]
