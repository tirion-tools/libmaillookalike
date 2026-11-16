# Gate toolchain (tools/container.sh). Ubuntu 26.04 by digest; packages from a dated Ubuntu snapshot at exact
# versions (apt verifies the signed InRelease): GCC 15, clang 21 (ASan, UBSan, libFuzzer), CMake, Ninja, ICU 78.2
# (Unicode 17), libpsl 0.21.2 and GoogleTest. ICU's version matters: the IDN display decision follows Chromium's
# expectations on ICU 78.
FROM ubuntu@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96
ARG SNAPSHOT=https://snapshot.ubuntu.com/ubuntu/20261112T000000Z
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates >/dev/null \
 && rm -f /etc/apt/sources.list.d/* \
 && printf 'deb %s resolute main universe\ndeb %s resolute-updates main universe\ndeb %s resolute-security main universe\n' \
      "$SNAPSHOT" "$SNAPSHOT" "$SNAPSHOT" > /etc/apt/sources.list \
 && apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      build-essential=12.12ubuntu2.26.04.2 cmake=4.2.3-2ubuntu2 ninja-build=1.13.2-1 pkg-config=2.5.1-4 \
      git=1:2.53.0-1ubuntu1.1 clang=1:21.1.6-71 lld=1:21.1.6-71 llvm=1:21.1.6-71 libclang-rt-dev=1:21.1.6-71 \
      libicu-dev=78.2-2ubuntu1 libpsl-dev=0.21.2-1.1build2 libgtest-dev=1.17.0-1build1 >/dev/null \
 && rm -rf /var/lib/apt/lists/*
