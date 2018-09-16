#!/usr/bin/env bash

# Please Use Google Shell Style: https://google.github.io/styleguide/shell.xml

# ---- Start unofficial bash strict mode boilerplate
# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -o errexit  # always exit on error
set -o errtrace # trap errors in functions as well
set -o pipefail # don't ignore exit codes when piping output
set -o posix    # more strict failures in subshells
# set -x          # enable debugging

IFS="$(printf "\n\t")"
# ---- End unofficial bash strict mode boilerplate

cd "$(dirname "${BASH_SOURCE[0]}")/.."
# The backslash escaped variables below are so bash doesn't immediately
# replace them with their environment variable values before passing to docker
dockerfile=$(
  cat <<EOF
# Based on https://github.com/rust-lang-nursery/docker-rust-nightly/blob/master/nightly/Dockerfile
FROM buildpack-deps:stretch
ARG USER
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN addgroup --gid \${GROUP_ID} \${USER}; \
  adduser --disabled-password --gid \${GROUP_ID} --uid \${USER_ID} --gecos \${USER} \${USER}
USER ${USER}
WORKDIR /opt
ENV \
  PATH=/home/${USER}/.cargo/bin:/opt/target/debug:\${PATH}
RUN set -eux; \
  cd; \
  wget --quiet "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"; \
  chmod +x rustup-init; \
  ./rustup-init -y --no-modify-path --default-toolchain nightly-2018-09-13; \
  rustup component add clippy-preview; \
  rm rustup-init; \
  rustup component add clippy-preview rustfmt-preview;
EOF
)
# chown -R \${USER}:\${GROUP_ID} /opt/target/registry;
echo "${dockerfile}" | docker build \
  --tag "$(basename "${PWD}")" \
  --build-arg "USER=${USER}" \
  --build-arg "USER_ID=$(id -u)" \
  --build-arg "GROUP_ID=$(id -g)" \
  -
