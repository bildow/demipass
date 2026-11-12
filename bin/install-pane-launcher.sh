#!/usr/bin/env bash
# Install the DemiPass pane launcher to ~/.local/bin/demipass-pane-mcp.js, pinned to one release.
#
#   bin/install-pane-launcher.sh <release-sha>
#
# The release must already be unpacked at ~/.local/share/demipass/releases/<sha>/ (mcp-server.js present). The launcher
# is taken from that release (bin/demipass-pane-mcp.js) so launcher and SDK come from the same reviewed commit; a
# release that predates the launcher being in the repo uses the copy next to this script, and the output says so.
# Never reads ~/.mcp.json or any credential and prints only paths and the sha. The previous launcher is kept as .bak.
set -euo pipefail
umask 077

sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <release-sha>   (full 40-character lowercase commit sha)" >&2
  exit 2
fi
release="$HOME/.local/share/demipass/releases/$sha"
if [[ ! -f "$release/mcp-server.js" ]]; then
  echo "install-pane-launcher: no release at $release (mcp-server.js missing); unpack that commit there first" >&2
  exit 1
fi
if [[ -f "$release/bin/demipass-pane-mcp.js" ]]; then
  src="$release/bin/demipass-pane-mcp.js"; from="release $sha"
else
  src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demipass-pane-mcp.js"; from="this checkout (release $sha has no bin/demipass-pane-mcp.js)"
fi
[[ -f "$src" ]] || { echo "install-pane-launcher: launcher source not found: $src" >&2; exit 1; }
count="$(grep -c '@@DEMIPASS_RELEASE_SHA@@' "$src" || true)"
if [[ "$count" != "1" ]]; then
  echo "install-pane-launcher: $src does not carry exactly one release placeholder; refusing" >&2
  exit 1
fi

dest_dir="$HOME/.local/bin"
dest="$dest_dir/demipass-pane-mcp.js"
mkdir -p "$dest_dir"
tmpd="$(mktemp -d "$dest_dir/.demipass-pane-mcp.XXXXXX")"
trap 'rm -rf "$tmpd"' EXIT
tmp="$tmpd/demipass-pane-mcp.js"
sed "s/@@DEMIPASS_RELEASE_SHA@@/$sha/" "$src" > "$tmp"
grep -q "const RELEASE = '$sha';" "$tmp" || { echo "install-pane-launcher: pin did not apply; refusing" >&2; exit 1; }
node --check "$tmp"
chmod 0700 "$tmp"
# The old .bak (file or symlink) is removed first so the backup is never written through a symlink (#20 review).
rm -f "$dest.bak"
if [[ -e "$dest" ]]; then cp -p "$dest" "$dest.bak"; fi
mv -f "$tmp" "$dest"
echo "installed $dest (mode 0700) pinned to $sha"
echo "launcher source: $from"
echo "running panes keep their old launcher until their MCP restarts (/mcp in Claude Code)"
