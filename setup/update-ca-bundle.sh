#!/usr/bin/env bash

echo "Updating CA bundle in IPA"

# Update CA trust bundle
podman exec ipa ipa-cacert-manage install /certs/tmp/ca-bundle.crt
podman exec ipa ipa-certupdate
