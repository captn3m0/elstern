package in.captnemo.elstern;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;

final class Device {
    private static final String ALIAS = "elstern";

    final String clientId, tokenId;
    final PrivateKey key;
    final byte[] cert;

    private Device(String clientId, String tokenId, PrivateKey key, byte[] cert) {
        this.clientId = clientId;
        this.tokenId = tokenId;
        this.key = key;
        this.cert = cert;
    }

    // ids and the login key are created on first use and kept for the life of the install
    static synchronized Device load(Context c) throws Exception {
        SharedPreferences prefs = c.getSharedPreferences("s", 0);
        if (!prefs.contains("cid")) {
            byte[] token = new byte[62];
            Codec.RANDOM.nextBytes(token);
            prefs.edit().putString("cid", UUID.randomUUID().toString().toUpperCase())
                    .putString("tid", Codec.encodeUrl(token)).commit();
        }
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(ALIAS)) generateKey(hasScreenLock(c));
        return new Device(prefs.getString("cid", ""), prefs.getString("tid", ""),
                (PrivateKey) ks.getKey(ALIAS, null), ks.getCertificate(ALIAS).getEncoded());
    }

    static boolean hasScreenLock(Context c) {
        return c.getSystemService(KeyguardManager.class).isDeviceSecure();
    }

    private static void generateKey(boolean requireUnlock) throws Exception {
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateSubject(new X500Principal("CN=Android Keystore Key"));
        if (requireUnlock) spec.setUserAuthenticationParameters(30,
                KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        g.initialize(spec.build());
        g.generateKeyPair();
    }
}
