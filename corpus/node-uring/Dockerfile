ARG NODE_BASE=node:22-alpine
FROM debian:bookworm-slim AS helper
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev liburing-dev
COPY corpus/node-uring/uring-helper.c /src/uring-helper.c
RUN gcc -O2 -static /src/uring-helper.c -luring -o /uring-helper
FROM ${NODE_BASE}
COPY --from=helper /uring-helper /workload/uring-helper
COPY corpus/node-uring/main.js /workload/uring.js
ENTRYPOINT ["node", "/workload/uring.js"]
