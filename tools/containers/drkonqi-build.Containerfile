FROM docker.io/library/debian@sha256:38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16
ARG RECIPE_SHA
LABEL org.shadowfetch.build-recipe=$RECIPE_SHA
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake debhelper bubblewrap pkg-config patch qt6-base-dev \
    libsystemd-dev python3 ca-certificates gpg \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp
