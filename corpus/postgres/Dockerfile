FROM debian:bookworm AS build
ARG POSTGRES_VERSION=18.0
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates curl bzip2 pkg-config libreadline-dev zlib1g-dev liburing-dev bison flex && apt-get clean
WORKDIR /build
RUN curl -fsSLO https://ftp.postgresql.org/pub/source/v${POSTGRES_VERSION}/postgresql-${POSTGRES_VERSION}.tar.bz2 && \
    curl -fsSLO https://ftp.postgresql.org/pub/source/v${POSTGRES_VERSION}/postgresql-${POSTGRES_VERSION}.tar.bz2.sha256 && \
    sha256sum -c postgresql-${POSTGRES_VERSION}.tar.bz2.sha256 && \
    tar -xjf postgresql-${POSTGRES_VERSION}.tar.bz2 && \
    cd postgresql-${POSTGRES_VERSION} && ./configure --prefix=/opt/pgsql --with-liburing --without-icu && make -j2 && make install

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libreadline8 zlib1g liburing2 && apt-get clean && \
    groupadd --gid 10001 sentrycheck && useradd --uid 10001 --gid 10001 --no-create-home sentrycheck
COPY --from=build /opt/pgsql /opt/pgsql
ENV PATH=/opt/pgsql/bin:/usr/bin:/bin
RUN mkdir /seed && chown 10001:10001 /seed
USER 10001:10001
RUN initdb -D /seed -U sentrycheck -A trust --locale=C --no-sync && chmod -R go+rX /seed
CMD ["postgres", "--version"]
