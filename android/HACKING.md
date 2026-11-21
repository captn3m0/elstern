## Code

- `Main` is the screen
- `Elster` handles the protocol, `Device` the key and ids
- `Link` parses links, `Codec` does base64, DER, JWS and AES-GCM

The only dependency is zxing-core (Apache-2.0) for the QR scanner, since Android has no
QR decoder of its own.

## Building

```sh
cd android
gradle assembleRelease
gradle testDebugUnitTest
```

For F-Droid, bump `versionCode` and `versionName` in `app/build.gradle` and tag
`android/<version>` (`UpdateCheckMode: Tags`).

## Signing

The release key is in `pass` at `elstern/android-release` (line 1: password, line 2:
base64 PKCS12):

```sh
E=$(pass show elstern/android-release); export KS_PASS=$(sed -n 1p <<<"$E")
export KS_FILE=$(mktemp); sed -n 2p <<<"$E" | base64 -d > $KS_FILE
gradle assembleRelease; shred -u $KS_FILE
```
