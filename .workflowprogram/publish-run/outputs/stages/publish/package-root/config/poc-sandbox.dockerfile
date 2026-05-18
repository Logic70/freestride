FROM alpine:3.19

# Minimal sandbox for STRIDE PoC execution
RUN apk add --no-cache \
    python3 \
    py3-pip \
    gcc \
    musl-dev \
    bash \
    curl

# Create isolated user
RUN adduser -D -s /bin/bash sandbox

# Work directory
WORKDIR /poc
RUN chown sandbox:sandbox /poc

# Drop all capabilities, no network
USER sandbox

# Entry point: expects /poc/run.sh
ENTRYPOINT ["/bin/bash", "/poc/run.sh"]
