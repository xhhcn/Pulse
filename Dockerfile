# Multi-stage build for minimal image size

# Stage 1: Build Go backend
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS backend-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/*.go ./
# Create empty web/dist directory for embed (actual files served by Nginx in Docker mode)
RUN mkdir -p web/dist && touch web/dist/.gitkeep
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o probe-server .

# Stage 2: Build frontend on the NATIVE build platform.
#
# The frontend output is a static HTML/JS/CSS bundle — completely
# architecture-independent — so we never need to build it under the
# target platform. Omitting `--platform=$BUILDPLATFORM` causes buildx
# to run this stage under QEMU emulation when building linux/arm64 on
# an amd64 runner, and `npm ci` (via its native `node-gyp` / V8
# bootstrap code) crashes with "qemu: uncaught target signal 4
# (Illegal instruction) - core dumped". Pinning to the BUILD platform
# avoids emulation entirely and makes arm64 builds as fast as amd64.
FROM --platform=$BUILDPLATFORM node:20-alpine AS frontend-builder
WORKDIR /build
COPY server/web/package*.json ./
RUN npm ci
COPY server/web/ ./
RUN npm run build

# Stage 3: Final minimal image with nginx
FROM alpine:3.22

# Install nginx and supervisor
RUN apk add --no-cache nginx supervisor && \
    mkdir -p /run/nginx /var/log/supervisor /app/data

# Copy backend binary
COPY --from=backend-builder /build/probe-server /app/probe-server

# Copy frontend static files
COPY --from=frontend-builder /build/dist /usr/share/nginx/html

# Copy nginx config
COPY docker/nginx.conf /etc/nginx/nginx.conf

# Copy supervisor config
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Set working directory
WORKDIR /app

# Expose port (default 8008, can be changed via docker-compose)
EXPOSE 8008

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8008/healthz || exit 1

# Start supervisor (manages both nginx and backend)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
