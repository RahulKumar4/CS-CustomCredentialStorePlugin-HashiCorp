#!/usr/bin/env bash
# macOS / Linux build helper. Windows users: build.ps1
#
#   ./build.sh              restore + build
#   ./build.sh --harness    + run the offline logic checks
#   ./build.sh --clean      wipe bin/obj first
set -euo pipefail
cd "$(dirname "$0")"

DLL_NAME="UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox.dll"
RUN_HARNESS=0

for arg in "$@"; do
  case "$arg" in
    --harness) RUN_HARNESS=1 ;;
    --clean)   rm -rf bin obj tools/Harness/bin tools/Harness/obj; echo "cleaned" ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

command -v dotnet >/dev/null 2>&1 || {
  echo "dotnet not found. Install with:  brew install --cask dotnet-sdk" >&2
  exit 1
}

echo "== SDK =="
dotnet --version

# A stale obj/ from an earlier build is the usual cause of CS0579 duplicate-attribute errors.
# Cheap to remove, so do it unconditionally.
rm -rf obj bin tools/Harness/obj tools/Harness/bin

echo "== restore =="
if ! dotnet restore; then
  cat >&2 <<'MSG'

restore failed. Almost always one of:
  1. No route to nuget.org from this network.
  2. UiPath.Orchestrator.Extensibility not on your configured feed.

Fix by pointing at your internal mirror, or by dropping the two .nupkg files into
./local-packages and adding a NuGet.config alongside this script:

  <?xml version="1.0" encoding="utf-8"?>
  <configuration>
    <packageSources>
      <add key="local" value="./local-packages" />
    </packageSources>
  </configuration>
MSG
  exit 1
fi

echo "== build =="
dotnet build -c Release --nologo

DLL="bin/Release/${DLL_NAME}"
[ -f "$DLL" ] || { echo "expected output missing: $DLL" >&2; exit 1; }

echo
echo "Built: $(cd "$(dirname "$DLL")" && pwd)/$(basename "$DLL")"
ls -lh "$DLL" | awk '{print "  size:", $5, " modified:", $6, $7, $8}'
echo
echo "Staged in bin/Release:"
for f in "${DLL_NAME}" appsettings.Production.merge.json DEPLOY.txt; do
  [ -f "bin/Release/$f" ] && echo "  - $f"
done
echo
echo "Next: read bin/Release/DEPLOY.txt. The DLL goes in <install>\\plugins\\;"
echo "the json is a MERGE fragment - do not overwrite the proxy's appsettings.Production.json."

if [ "$RUN_HARNESS" -eq 1 ]; then
  echo
  echo "== harness =="
  dotnet run -c Release --project tools/Harness/Harness.csproj
fi
