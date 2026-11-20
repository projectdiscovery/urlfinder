# Pinning apk package versions breaks the build once Alpine drops them; the base image tag is the pin.
# hadolint global ignore=DL3018
FROM alpine:3.24
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/urlfinder /usr/local/bin/

ENTRYPOINT ["urlfinder"]
