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

docker_build() {
  dockerfile=$(
    cat <<'EOF'

    # rustup component add clippy-preview; \
    # rustup component add clippy-preview rustfmt-preview;
# Based on https://github.com/rust-lang-nursery/docker-rust-nightly/blob/master/nightly/Dockerfile
FROM buildpack-deps:stretch
ARG USER
ARG USER_ID=1000
ARG GROUP_ID=1000
# This flavor is good for debian/ubuntu
RUN addgroup --gid ${GROUP_ID} ${USER}; \
  grep nope /etc/passwd; \
  adduser --disabled-password --gid ${GROUP_ID} --uid ${USER_ID} --gecos ${USER} ${USER}; \
  set -eux; \
  apt-get -q update; \
  apt-get -q -y install less;
WORKDIR /host
USER ${USER}
ENV \
  PATH=/home/${USER}/.cargo/bin:/host/target/debug:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN set -eux; \
  cd; \
  wget --quiet "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"; \
  chmod +x rustup-init; \
  ./rustup-init -y --no-modify-path --default-toolchain nightly-2018-09-13; \
  rm rustup-init; \
  rustup component add clippy-preview rustfmt-preview;
EOF
)

  echo "${dockerfile}" | docker build \
    --tag "$1" \
    --build-arg "USER=${USER}" \
    --build-arg "USER_ID=$(id -u)" \
    --build-arg "GROUP_ID=$(id -g)" \
    -
}

docker_run() {
  exec docker run --rm --interactive --tty \
    --attach stdin --attach stdout --attach stderr \
    --volume "${PWD}:/host" \
    --volume $SSH_AUTH_SOCK:/ssh-agent \
    --env SSH_AUTH_SOCK=/ssh-agent \
    --user "$(id -u)" \
    --publish 9999:9999 \
    "$1" "${2-bash}"
}

main() {
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  image=$(basename "${PWD}")
  mkdir -p ./target/registry
  case "$1" in
  --build)
    docker_build "${image}"
    ;;
  *)
    if ! docker inspect "${image}" &>/dev/null; then
      docker_build "${image}"
    fi
    docker_run "${image}"
    ;;
  esac
}

main "$@"
