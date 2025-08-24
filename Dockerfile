# syntax=docker/dockerfile:1
# See: https://docs.docker.com/engine/reference/builder/

FROM jasontheiler/cargoverse AS base
WORKDIR /app/


FROM base AS dev
COPY ./ ./
ENV RUST_LOG=trace
CMD [ "cargo", "watch", "-x", "run" ]

FROM base AS build
COPY ./ ./
RUN cargo build --release

FROM debian:stable-slim AS final
RUN --mount=type=cache,target=/var/cache/apt/,sharing=locked \
  --mount=type=cache,target=/var/lib/apt/,sharing=locked \
  <<EOF
    apt update
    apt install -y --no-install-recommends ca-certificates
EOF
COPY --from=build /app/target/release/bouncy /usr/local/bin/
CMD [ "bouncy" ]

