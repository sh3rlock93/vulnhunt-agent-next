#!/bin/zsh
set -euo pipefail

usage() {
    print -u2 "usage: $0 /absolute/path/to/imageio-vm-bridge"
    exit 64
}

[[ $# -eq 1 ]] || usage
bridge_root=$1
[[ $bridge_root == /* && $bridge_root != *..* ]] || usage

script_directory=${0:A:h}
repository_root=${script_directory:h:h}
control_directory=$bridge_root/control
payload_directory=$control_directory/payload

mkdir -p -m 700 "$control_directory" "$payload_directory"

temporary_directory=$(mktemp -d "$payload_directory/.build.XXXXXXXX")
cleanup() {
    rm -rf "$temporary_directory"
}
trap cleanup EXIT INT TERM

export CLANG_MODULE_CACHE_PATH=$temporary_directory/clang-module-cache
export SWIFT_MODULECACHE_PATH=$temporary_directory/swift-module-cache

xcrun swiftc \
    "$repository_root/tools/macos/imageio_harness.swift" \
    -o "$temporary_directory/imageio-harness"
xcrun clang -std=c17 -Wall -Wextra -Werror \
    "$repository_root/tools/macos/imageio_job_runner.c" \
    -o "$temporary_directory/imageio-job-runner"
xcrun swiftc \
    "$repository_root/tools/macos/imageio_vm_worker.swift" \
    -o "$temporary_directory/imageio-vm-worker"

for binary in imageio-harness imageio-job-runner imageio-vm-worker; do
    codesign --force --sign - "$temporary_directory/$binary"
    install -m 0755 "$temporary_directory/$binary" "$payload_directory/$binary"
done

(
    cd "$payload_directory"
    shasum -a 256 imageio-harness imageio-job-runner imageio-vm-worker \
        > payload-sha256.txt.new
    chmod 0600 payload-sha256.txt.new
    mv -f payload-sha256.txt.new payload-sha256.txt
)
install -m 0755 \
    "$repository_root/tools/macos/install_imageio_vm_worker.sh" \
    "$control_directory/install-imageio-vm-worker.sh"

print "ImageIO VM payload is ready at $payload_directory"
print "Run this once in the guest:"
print 'zsh "/Volumes/My Shared Files/imageio-vm-bridge/control/install-imageio-vm-worker.sh"'
