FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake g++ ninja-build libsqlite3-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DTENRIFF_SERVER_BUILD_TESTS=ON \
    && cmake --build build \
    && ctest --test-dir build --output-on-failure

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/tenriff-server /usr/local/bin/tenriff-server
EXPOSE 27300/tcp 27302/tcp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tenriff-server"]
CMD ["--bind", "0.0.0.0", "--port", "27300", "--api-port", "27302"]
