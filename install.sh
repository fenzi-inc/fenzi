#!/bin/sh
# Install the fenzi command, then start its guided setup when a person is
# at the terminal. Setup asks before it installs the sandbox runtime.
#   FENZI_VERSION=0.1.1        install that release instead of the latest
#   FENZI_INSTALL_DIR=dir      install there
#   FENZI_NO_MODIFY_PATH=1     never edit a shell profile
#   FENZI_NO_SETUP=1           install the command and stop
set -eu

base="${FENZI_DOWNLOAD_BASE:-https://fenzi.dev/dl}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  accent=$(printf '\033[94m'); bold=$(printf '\033[1m'); dim=$(printf '\033[2m'); off=$(printf '\033[0m')
else
  accent=""; bold=""; dim=""; off=""
fi

say() { printf '  %s\n' "$*"; }
done_() { printf '  %s✓%s %-17s %s\n' "$accent" "$off" "$1" "$2"; }
fail() { printf '\n  %s!%s %s\n\n' "$bold" "$off" "$*" >&2; exit 1; }

os=$(uname -s)
case "$os" in
  Darwin) goos=darwin; pretty="macOS" ;;
  Linux) goos=linux; pretty="Linux" ;;
  *) fail "This installer supports macOS and Linux. This machine is ${os}." ;;
esac

machine=$(uname -m)
case "$machine" in
  arm64|aarch64) goarch=arm64 ;;
  x86_64|amd64) goarch=amd64 ;;
  *) fail "This installer supports arm64 and amd64, not ${machine}." ;;
esac

version="${FENZI_VERSION:-}"
if [ -z "$version" ]; then
  version=$(curl -fsSL "${base}/latest.txt" | tr -d '[:space:]') || fail "Could not find the latest release: ${base}/latest.txt"
fi
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "\"${version}\" is not a release number." ;;
esac

name="fenzi-${version}-${goos}-${goarch}"
if [ -n "${FENZI_INSTALL_DIR:-}" ]; then
  dest=$FENZI_INSTALL_DIR
  mkdir -p "$dest"
elif [ -w /usr/local/bin ]; then
  dest=/usr/local/bin
else
  dest="${HOME}/.local/bin"
  mkdir -p "$dest"
fi
installed="${dest}/fenzi"
shown=$(printf '%s' "$installed" | sed "s|^${HOME}/|~/|")

echo ""
printf '  %s■%s %sFenzi%s %s\n' "$accent" "$off" "$bold" "$off" "${dim}${version} for ${pretty}, ${goarch}${off}"
echo ""

tmp=$(mktemp)
sums=$(mktemp)
trap 'rm -f "$tmp" "$sums"' EXIT

curl -fsSL "${base}/${name}" -o "$tmp" || fail "The download failed: ${base}/${name}"
curl -fsSL "${base}/fenzi-${version}-sha256.txt" -o "$sums" || fail "The checksum download failed."
done_ "Downloaded" "$name"

expected=$(awk -v name="$name" '$2 == name { print $1 }' "$sums")
[ -n "$expected" ] || fail "There is no checksum for ${name}."
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "$tmp" | awk '{ print $1 }')
fi
[ "$actual" = "$expected" ] || fail "The checksum did not match for ${name}. Nothing was installed."
done_ "Checksum" "sha256 matches"

chmod 0755 "$tmp"
mv "$tmp" "$installed"
trap 'rm -f "$sums"' EXIT
done_ "Installed" "$shown"

found=$(command -v fenzi 2>/dev/null || true)
if [ -n "$found" ] && [ "$found" != "$installed" ]; then
  echo ""
  say "${bold}Your shell runs a different fenzi first:${off} ${found}"
  say "${dim}Put ${dest} earlier in PATH, or call the new one by its full path.${off}"
fi

# Put dest on PATH for new shells: one marked line in the profile of the
# login shell, written once. The line uses $HOME so the profile stays portable.
marker="# added by the fenzi installer"
profile=""
on_path=no
case ":${PATH}:" in *":${dest}:"*) on_path=yes ;; esac
if [ "$on_path" = no ] && [ -z "${FENZI_NO_MODIFY_PATH:-}" ]; then
  dir_expr=$(printf '%s' "$dest" | sed "s|^${HOME}/|\$HOME/|")
  case "$(basename "${SHELL:-sh}")" in
    zsh) profile="${ZDOTDIR:-$HOME}/.zshrc"; line="export PATH=\"${dir_expr}:\$PATH\" ${marker}" ;;
    bash)
      if [ "$goos" = darwin ]; then profile="${HOME}/.bash_profile"; else profile="${HOME}/.bashrc"; fi
      line="export PATH=\"${dir_expr}:\$PATH\" ${marker}" ;;
    fish) profile="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/fenzi.fish"; line="fish_add_path \"${dir_expr}\" ${marker}" ;;
  esac
  if [ -n "$profile" ]; then
    if [ -f "$profile" ] && grep -qF "$marker" "$profile"; then
      :
    elif mkdir -p "$(dirname "$profile")" && printf '\n%s\n' "$line" >> "$profile"; then
      :
    else
      profile=""
    fi
  fi
fi
if [ -n "$profile" ]; then
  shown_profile=$(printf '%s' "$profile" | sed "s|^${HOME}/|~/|")
  done_ "PATH" "$(printf '%s' "$dest" | sed "s|^${HOME}/|~/|") added in ${shown_profile}"
  export FENZI_PATH_PROFILE="$shown_profile"
fi

if [ -z "${FENZI_NO_SETUP:-}" ] && [ -t 1 ] && (exec </dev/tty) 2>/dev/null; then
  exec "$installed" setup </dev/tty
fi

echo ""
if [ -n "$profile" ]; then
  say "Open a new terminal, or run ${bold}source ${shown_profile}${off}, so this one finds fenzi."
  echo ""
elif [ "$on_path" = no ] && [ -z "$found" ]; then
  say "Your shell cannot find fenzi yet. Add its folder to PATH:"
  echo ""
  say "  ${bold}export PATH=\"${dest}:\$PATH\"${off}"
  echo ""
fi
say "Next, a guided setup checks this machine, picks your agent, and stores its key:"
echo ""
say "  ${bold}fenzi setup${off}"
echo ""
say "${dim}Docs: https://fenzi.dev/docs${off}"
echo ""
