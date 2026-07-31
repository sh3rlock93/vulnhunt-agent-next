#!/bin/zsh
set -euo pipefail

if [[ $(uname -m) != arm64 ]]; then
    print -u2 "the ImageIO VM worker requires an arm64 macOS guest"
    exit 69
fi

control_directory=${0:A:h}
bridge_root=${control_directory:h}
payload_directory=$control_directory/payload
manifest=$payload_directory/payload-sha256.txt

[[ -f $manifest ]] || {
    print -u2 "payload digest manifest is missing"
    exit 66
}
(
    cd "$payload_directory"
    shasum -a 256 -c "${manifest:t}"
)

application_directory=$HOME/Library/Application\ Support/VulnHunt
binary_directory=$application_directory/bin
log_directory=$HOME/Library/Logs/VulnHunt
agent_directory=$HOME/Library/LaunchAgents
agent_path=$agent_directory/io.vulnhunt.imageio-worker.plist
temporary_agent=$agent_directory/.io.vulnhunt.imageio-worker.plist.new
service_target=gui/$(id -u)

mkdir -p -m 700 "$binary_directory" "$log_directory" "$agent_directory"
for binary in imageio-harness imageio-job-runner imageio-vm-worker \
    imageio-canary-interposer.dylib; do
    install -m 0755 "$payload_directory/$binary" "$binary_directory/$binary"
done

rm -f "$temporary_agent"
plutil -create xml1 "$temporary_agent"
plutil -insert Label -string io.vulnhunt.imageio-worker "$temporary_agent"
plutil -insert ProgramArguments -xml '<array/>' "$temporary_agent"
plutil -insert ProgramArguments.0 -string \
    "$binary_directory/imageio-vm-worker" "$temporary_agent"
plutil -insert ProgramArguments.1 -string --bridge "$temporary_agent"
plutil -insert ProgramArguments.2 -string "$bridge_root" "$temporary_agent"
plutil -insert RunAtLoad -bool true "$temporary_agent"
plutil -insert KeepAlive -bool true "$temporary_agent"
plutil -insert ProcessType -string Background "$temporary_agent"
plutil -insert StandardOutPath -string "$log_directory/worker.stdout.log" \
    "$temporary_agent"
plutil -insert StandardErrorPath -string "$log_directory/worker.stderr.log" \
    "$temporary_agent"
chmod 0600 "$temporary_agent"
mv -f "$temporary_agent" "$agent_path"

launchctl bootout "$service_target/io.vulnhunt.imageio-worker" 2>/dev/null || true
launchctl bootstrap "$service_target" "$agent_path"
launchctl kickstart -k "$service_target/io.vulnhunt.imageio-worker"

print "Installed the networkless ImageIO VM worker."
print "Bridge: $bridge_root"
print "Binaries: $binary_directory"
