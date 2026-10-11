#!/bin/sh
# Download and unpack chosen PyPI malware samples from the Datadog dataset. Run it yourself, in a
# terminal: it only downloads and unzips (password "infected"); nothing is installed or run.
set -e
DATASET="$HOME/malware-samples/dataset"
OUT="$HOME/malware-samples/extracted2"
PACKAGES="botoceor botocote cloud-client cloud-datasets cloudfix cloudx-base env-loader-cli
exo-steal pycryptoenv s3transfer-sl salamus3 secretinspector tiketoken tktoken tls-bypass
keystackutilities herewalletbot kubespy spyware spyme xolotopgrabber discord-hook oauth20-api
tdwtauthauthentication loggerbyxolo pyrologin cryptowallet-safety"

cd "$DATASET"
for p in $PACKAGES; do git sparse-checkout add "samples/pypi/malicious_intent/$p"; done
mkdir -p "$OUT"
for zip in $(find samples/pypi/malicious_intent -name '*.zip'); do
  case "$zip" in
    *aiiohttp*|*aioconsol*|*aiohtttp*|*aiopbotocore*) continue ;;
  esac
  name=$(echo "$zip" | cut -d/ -f4)-$(echo "$zip" | cut -d/ -f5)
  unzip -q -o -P infected "$zip" -d "$OUT/$name"
done
ls "$OUT"
