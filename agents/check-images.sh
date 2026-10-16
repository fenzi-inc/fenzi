#!/usr/bin/env bash
# Build agent images for one platform and check the binaries agent.yaml names.
#
#   agents/check-images.sh [--platform linux/amd64|linux/arm64] [agent ...]
#
# With no agent, every folder under agents/ that has both agent.yaml and a
# Dockerfile is checked. With no platform, the Docker server's own is used.
#
# For each agent the image is built from its Dockerfile alone, as
# `boundlane agents build` does, with --pull so the base image is current.
# Then, inside the image, as the image's own user and without network, each
# path agent.yaml lists for that processor must:
#
#   - exist,
#   - be its own real path (the sandbox matches the path the kernel resolves,
#     so a link there would never match),
#   - be a regular file the user can execute,
#   - be a Linux ELF program for that processor.
#
# Paths that name a processor (codex lists one per processor) are only
# checked on that processor; see BinariesFor in agents.go.
#
# Images are built with docker buildx when it is installed, and loaded into
# the local image store. Nothing is pushed. Without buildx, docker build is
# used for the server's own platform only. Another platform needs buildx and
# QEMU registered with binfmt. The built image's platform is checked too.
# They are tagged boundlane-image-check/<agent>:<arch> and removed at the
# end; set KEEP_IMAGES=1 to keep them. No other image or container is
# touched.
#
# Exit status: 0 when every check passes, 1 when any fails, 2 on misuse.
set -euo pipefail

usage() {
	echo "usage: $0 [--platform linux/amd64|linux/arm64] [agent ...]" >&2
	exit 2
}

root=$(cd "$(dirname "$0")/.." && pwd)
platform=""
agents=()
while [ $# -gt 0 ]; do
	case "$1" in
	--platform) [ $# -ge 2 ] || usage; platform=$2; shift 2 ;;
	--platform=*) platform=${1#--platform=}; shift ;;
	-h | --help) usage ;;
	-*) echo "unknown option $1" >&2; usage ;;
	*) agents+=("$1"); shift ;;
	esac
done

command -v docker >/dev/null || { echo "docker is not installed" >&2; exit 2; }
command -v go >/dev/null || { echo "go is not installed" >&2; exit 2; }

native="linux/$(docker version --format '{{.Server.Arch}}')"
platform=${platform:-$native}
case "$platform" in
linux/amd64) arch=amd64 machine=3e00 ;; # ELF e_machine 62, x86-64
linux/arm64) arch=arm64 machine=b700 ;; # ELF e_machine 183, AArch64
*) echo "unsupported platform $platform; use linux/amd64 or linux/arm64" >&2; exit 2 ;;
esac

if [ ${#agents[@]} -eq 0 ]; then
	for d in "$root"/agents/*/; do
		d=${d%/}
		if [ -f "$d/agent.yaml" ] && [ -f "$d/Dockerfile" ]; then
			agents+=("$(basename "$d")")
		fi
	done
fi
[ ${#agents[@]} -gt 0 ] || { echo "no agent folders found under $root/agents" >&2; exit 2; }

if docker buildx version >/dev/null 2>&1; then
	build=(docker buildx build --load --progress=plain)
elif [ "$platform" = "$native" ]; then
	build=(docker build)
else
	# The legacy builder can ignore --platform and build the native image.
	echo "building for $platform on a $native Docker server needs docker buildx" >&2
	exit 2
fi

tmp=$(mktemp -d)
built=()
cleanup() {
	if [ "${KEEP_IMAGES:-}" != 1 ] && [ ${#built[@]} -gt 0 ]; then
		docker image rm "${built[@]}" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT

(cd "$root" && go build -o "$tmp/listbinaries" ./agents/listbinaries)

# Runs inside the image with sh. $1 is the expected e_machine bytes, the rest
# are the paths. Prints one line per problem and nothing when all pass.
check='want=$1; shift
for p in "$@"; do
	if [ ! -e "$p" ]; then
		if [ -L "$p" ]; then echo "$p: is a link to a missing file"; else echo "$p: missing"; fi
		continue
	fi
	real=$(readlink -f "$p")
	if [ "$real" != "$p" ]; then echo "$p: resolves to $real, and the sandbox matches the resolved path"; continue; fi
	if [ ! -f "$p" ]; then echo "$p: not a regular file"; continue; fi
	if [ ! -x "$p" ]; then echo "$p: not executable by $(id -un)"; continue; fi
	magic=$(od -An -tx1 -N4 "$p" | tr -d " \n")
	if [ "$magic" != 7f454c46 ]; then echo "$p: not an ELF program"; continue; fi
	got=$(od -An -tx1 -j18 -N2 "$p" | tr -d " \n")
	if [ "$got" != "$want" ]; then echo "$p: ELF machine $got, want $want"; fi
done'

failures=0
fail() {
	echo "FAIL $1 $platform: $2"
	failures=$((failures + 1))
}

for agent in "${agents[@]}"; do
	dir="$root/agents/$agent"
	if [ ! -f "$dir/Dockerfile" ] || [ ! -f "$dir/agent.yaml" ]; then
		fail "$agent" "agents/$agent needs agent.yaml and a Dockerfile"
		continue
	fi
	if ! "$tmp/listbinaries" "$agent" "$arch" >"$tmp/paths" 2>"$tmp/err"; then
		fail "$agent" "$(tr '\n' ' ' <"$tmp/err")"
		continue
	fi
	paths=()
	while IFS= read -r p; do paths+=("$p"); done <"$tmp/paths"

	tag="boundlane-image-check/$agent:$arch"
	echo "== $agent $platform: building $tag"
	if ! "${build[@]}" --pull --platform "$platform" -t "$tag" - <"$dir/Dockerfile"; then
		fail "$agent" "image build failed (a non-native platform needs QEMU registered with binfmt)"
		continue
	fi
	built+=("$tag")
	got=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$tag")
	if [ "$got" != "$platform" ]; then
		fail "$agent" "the image was built for $got"
		continue
	fi

	if ! docker run --rm --pull never --network none --platform "$platform" \
		--entrypoint /bin/sh "$tag" -c "$check" check "$machine" "${paths[@]}" >"$tmp/out" 2>"$tmp/err"; then
		fail "$agent" "the check could not run in the image: $(tr '\n' ' ' <"$tmp/err")"
		continue
	fi
	bad=0
	while IFS= read -r line; do
		fail "$agent" "$line"
		bad=1
	done <"$tmp/out"
	if [ $bad -eq 0 ]; then
		for p in "${paths[@]}"; do echo "ok   $agent $platform: $p"; done
	fi
done

echo "checked ${#agents[@]} agent(s) on $platform: $failures failure(s)"
[ $failures -eq 0 ]
