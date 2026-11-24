# macOS packaging

`build-pkg.sh` produces an unsigned, unnotarized installer package with the
universal `haven-idp` and `haven` binaries in `/usr/local/bin`. It does not sign,
notarize or read any credential. Those are manual steps for the release
maintainer, on the signing Mac (the Mac mini).

```sh
make macos-pkg VERSION=0.1.0          # or: bash packaging/macos/build-pkg.sh --version 0.1.0
# -> dist/macos/haven-0.1.0-unsigned.pkg
```

## Signing and notarizing (run these yourself)

Notarization needs every Mach-O binary inside the package to be signed with the
Developer ID Application identity, hardened runtime and a secure timestamp, and
the package itself to be signed with the Developer ID Installer identity. So
the order is: build universal binaries, sign them, package, sign the package,
notarize, staple.

```sh
# 1. universal binaries (no packaging yet)
for c in haven-idp haven; do
  for a in arm64 amd64; do GOOS=darwin GOARCH=$a CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /tmp/$c-$a ./cmd/$c; done
  lipo -create -output stage/$c /tmp/$c-arm64 /tmp/$c-amd64
  codesign --force --options runtime --timestamp --sign "<Developer ID Application identity>" stage/$c
done

# 2. package from the signed binaries
bash packaging/macos/build-pkg.sh --version 0.1.0 --prebuilt stage

# 3. sign the package with the Developer ID Installer identity
productsign --sign "<Developer ID Installer identity>" dist/macos/haven-0.1.0-unsigned.pkg dist/macos/haven-0.1.0.pkg

# 4. notarize and staple (keychain profile created once with `notarytool store-credentials`)
xcrun notarytool submit dist/macos/haven-0.1.0.pkg --keychain-profile "<profile>" --wait
xcrun stapler staple dist/macos/haven-0.1.0.pkg
spctl -a -vv -t install dist/macos/haven-0.1.0.pkg
```

Notes:

- Keychain-backed signing identities are often not reachable over plain `ssh`
  (`pkgbuild --sign` and `productsign` fail there). Run steps 1-4 from a script
  launched in the GUI session (for example `open -a Terminal script.command`)
  and click "Always Allow" once. This is why the build script itself never signs.
- Keep the App Store Connect API key (`.p8`) where it is; `notarytool` reads it
  through the keychain profile. Never copy it into the repository or a CI log.
- A bare command-line binary can be notarized inside a package or a zip, but it
  cannot be stapled on its own; staple the `.pkg`.
- The package installs no launchd job. Services are created per user with
  `haven-idp install-service` (see `docs/macos.md`), so install needs no
  postinstall script and no root-owned service account.
