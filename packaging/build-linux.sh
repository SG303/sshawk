#!/usr/bin/env bash
# Build the portable Linux binary inside an old distribution (AlmaLinux 8, glibc 2.28)
# so it also runs on older servers (RHEL/Rocky/Alma 8+, Debian 10+, Ubuntu 20.04+).
# Usage: packaging/build-linux.sh   (needs docker; result: dist/sshawk-linux-x86_64)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
image="${SSHAWK_BUILD_IMAGE:-quay.io/pypa/manylinux_2_28_x86_64}"
mkdir -p "$root/dist"  # create as the calling user, not as root via docker
read -ra docker <<< "${DOCKER:-docker}"  # e.g. DOCKER="sudo docker"

# shellcheck disable=SC2016  # variables expand inside the container
"${docker[@]}" run --rm \
  -v "$root:/src:ro" \
  -v "$root/dist:/out" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  "$image" bash -euo pipefail -c '
    curl -LsSf https://astral.sh/uv/install.sh | env UV_UNMANAGED_INSTALL=/usr/local/bin sh >/dev/null
    cp -r /src /build && cd /build
    rm -rf .venv build dist
    export UV_PYTHON_PREFERENCE=only-managed  # PyInstaller needs a shared libpython
    uv sync --frozen --no-dev --group build --python 3.13 --quiet
    uv run --no-sync python packaging/build.py >/dev/null
    install -m 755 -o "$HOST_UID" -g "$HOST_GID" dist/sshawk /out/sshawk-linux-x86_64
    ldd --version | sed -n 1p  # not head: an early-closed pipe fails under pipefail
  '
echo "built $root/dist/sshawk-linux-x86_64"
