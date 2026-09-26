# Linux x86_64 release bundle

This is the independent CompatForge input consumed by ForgeOS. It contains the
release CLI and FFI library, not Wine, DXVK, application binaries, or a runtime
store. The archive is a closed three-member tar.gz:

```text
manifest.json
bin/compatforge-cli
lib/libcompatforge_ffi.so
```

`manifest.json` is canonical JSON. Schema 1 binds the workspace version, exact
40-character source commit, `Cargo.lock` SHA-256, Linux x86_64 target, and the
SHA-256 and byte length of each binary. The bundler rejects a dirty checkout,
non-ELF or non-x86_64 binaries. Archive member ownership, timestamps and order
are fixed so packaging the same inputs yields identical bytes. It does not
claim compiler-level reproducibility across build hosts.

From a clean Linux checkout at the release commit:

```sh
umask 077
cargo build --release --locked -p compatforge-cli -p compatforge-ffi
python3 tools/package_linux_release.py build \
  --source-root . \
  --cli target/release/compatforge-cli \
  --library target/release/libcompatforge_ffi.so \
  --output /absolute/release/compatforge-linux-x86_64-v0.12.0.tar.gz
```

The command prints the bundle digest and manifest. Verify with an independently
recorded digest and source commit:

```sh
python3 tools/package_linux_release.py verify \
  --bundle /absolute/release/compatforge-linux-x86_64-v0.12.0.tar.gz \
  --sha256 "$EXPECTED_BUNDLE_SHA256" \
  --source-commit "$EXPECTED_SOURCE_COMMIT"
```

The release workflow builds the asset from a pushed tag, runs Linux gates,
generates a GitHub build-provenance attestation, and attaches the asset to a
prerelease. Tags use `linux-runtime-v<workspace version>-rc.<positive number>`.
For a downloaded release asset, verify its provenance before staging it:

```sh
gh attestation verify /absolute/release/compatforge-linux-x86_64-linux-runtime-v0.12.0-rc.1.tar.gz \
  -R lcxinc/CompatForge \
  --signer-workflow lcxinc/CompatForge/.github/workflows/linux-runtime-release.yml \
  --source-digest "$EXPECTED_SOURCE_COMMIT" \
  --source-ref refs/tags/linux-runtime-v0.12.0-rc.1
```

Consumers should pin the resulting
archive digest in their own source lock before any offline image build. A
local bundle is a candidate until that verification and release publication
have happened. Never substitute the manifest's self-declared commit or hashes
for the external release tag, attestation and ForgeOS source lock.

Rollback uses a previously published, attested archive and its matching
ForgeOS source-lock entry. No mutable `latest` URL is accepted by the image.
