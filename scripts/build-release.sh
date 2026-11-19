#!/usr/bin/env bash
# Build release archives for every platform into dist/.
#
#   scripts/build-release.sh v1.2.3
#
# Runs on macOS: the darwin builds need cgo for PC/SC (card read), which
# links PCSC.framework, present on every Mac. Linux builds are static
# (CGO_ENABLED=0) so they run without pcsc-lite installed; card read is
# unavailable in them (build from source with cgo to get it). Windows
# builds include PC/SC without cgo (winscard.dll is loaded at run time).
set -euo pipefail

version="${1:?usage: $0 VERSION}"
cd "$(dirname "$0")/.."
rm -rf dist
mkdir -p dist

if [[ "$(go env GOHOSTOS)" != darwin ]]; then
  echo "darwin builds need cgo with PCSC.framework: run this on macOS" >&2
  exit 1
fi

targets=(
  "darwin arm64 1"
  "darwin amd64 1"
  "linux amd64 0"
  "linux arm64 0"
  "windows amd64 0"
  "windows arm64 0"
)

for t in "${targets[@]}"; do
  read -r goos goarch cgo <<<"$t"
  name="idpdbg_${version}_${goos}_${goarch}"
  dir="dist/$name"
  mkdir -p "$dir"
  exe=idpdbg
  [[ $goos == windows ]] && exe=idpdbg.exe
  echo "building $name (cgo=$cgo)"
  GOOS=$goos GOARCH=$goarch CGO_ENABLED=$cgo \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$dir/$exe" .
  cp README.md "$dir/"
  [[ -f LICENSE ]] && cp LICENSE "$dir/"
  if [[ $goos == windows ]]; then
    (cd dist && zip -qr "$name.zip" "$name")
  else
    tar -C dist -czf "dist/$name.tar.gz" "$name"
  fi
  rm -rf "$dir"
done

(cd dist && shasum -a 256 ./*.tar.gz ./*.zip | sed 's#\./##' > SHA256SUMS)

# Smoke-test the native binary.
native="idpdbg_${version}_darwin_$(go env GOHOSTARCH)"
tmp=$(mktemp -d)
tar -C "$tmp" -xzf "dist/$native.tar.gz"
out=$("$tmp/$native/idpdbg" version)
rm -rf "$tmp"
echo "$out"
[[ $out == "idpdbg $version "*"with PC/SC" ]] || { echo "unexpected version output" >&2; exit 1; }
cat dist/SHA256SUMS
