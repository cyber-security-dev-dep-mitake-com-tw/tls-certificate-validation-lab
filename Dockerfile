FROM rust:1-bookworm AS rust-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    perl make g++ pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust /src/rust
WORKDIR /src/rust
RUN cargo build --release -p svc1 -p harness -p harvester

FROM debian:bookworm-slim AS zig-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) arch=x86_64 ;; \
      arm64) arch=aarch64 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/0.17.1/zig-${arch}-linux-0.17.1.tar.xz" \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1
WORKDIR /src/zig/possession
COPY zig/possession /src/zig/possession
RUN /opt/zig/zig build -Doptimize=ReleaseSafe

FROM julia:1.12-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin lab \
    && mkdir -p /state /trust /reports \
    && chown lab:lab /state /trust /reports
COPY --from=rust-build /src/rust/target/release/svc1 /usr/local/bin/svc1
COPY --from=rust-build /src/rust/target/release/harness /usr/local/bin/harness
COPY --from=rust-build /src/rust/target/release/harvester /usr/local/bin/harvester
COPY --from=zig-build /src/zig/possession/zig-out/bin/possession /usr/local/bin/possession
COPY julia /opt/lab/julia
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /usr/local/bin/svc1 /usr/local/bin/harness /usr/local/bin/harvester /usr/local/bin/possession
ENV JULIA_GENERATE=/opt/lab/julia/generate.jl \
    JULIA_ANALYZE=/opt/lab/julia/analyze.jl \
    JULIA_ORACLE=/opt/lab/julia/oracle.jl \
    LAB_STATE=/state \
    LAB_TRUST=/trust \
    POSSESSION_BIN=/usr/local/bin/possession \
    LAB_LLM_PROVIDER=disabled
WORKDIR /opt/lab
ENTRYPOINT ["/entrypoint.sh"]
