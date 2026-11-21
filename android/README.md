# elstern for Android

Two Java files; the only dependency is zxing-core for QR decoding. The login key is a
non-exportable EC P-256 key in the Android Keystore. Requires Android 14+.

Open an `elster-secure://` or `https://www.elster.de/elstersecure` link (or paste
it into the app), then tap the button to enroll or log in.

```sh
cd android && gradle assembleRelease
```

The scanner uses zxing-core (Apache-2.0); Android has no
built-in QR decoder. The scanned link still needs the confirm tap.

F-Droid: build from `android/`, `UpdateCheckMode: Tags`, bump
`versionCode`/`versionName` in `app/build.gradle` per tag.

Release signing key lives in `pass` (`elstern/android-release`: line 1 password,
line 2 base64 PKCS12). Sign a build with:

```sh
E=$(pass show elstern/android-release); export KS_PASS=$(sed -n 1p <<<"$E")
export KS_FILE=$(mktemp); sed -n 2p <<<"$E" | base64 -d > $KS_FILE
gradle assembleRelease; shred -u $KS_FILE
```
