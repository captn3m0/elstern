package in.captnemo.elstern;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class Codec {
    static final SecureRandom RANDOM = new SecureRandom();

    private Codec() {
    }

    static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static String text(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    static byte[] decode(String s) {
        return Base64.getUrlDecoder().decode(s.trim().replace('+', '-').replace('/', '_'));
    }

    static String encode(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    static String encodeUrl(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static byte[] der(int tag, byte[]... parts) {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        for (byte[] p : parts) value.writeBytes(p);
        int n = value.size();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (n < 128) {
            out.write(n);
        } else {
            out.write(0x82);
            out.write(n >> 8);
            out.write(n);
        }
        out.writeBytes(value.toByteArray());
        return out.toByteArray();
    }

    static byte[] rawSignature(byte[] der) {
        byte[] raw = new byte[64];
        int pos = 2;
        for (int i = 0; i < 2; i++) {
            int len = der[pos + 1] & 0xff;
            int skip = Math.max(0, len - 32), n = len - skip;
            System.arraycopy(der, pos + 2 + skip, raw, i * 32 + 32 - n, n);
            pos += 2 + len;
        }
        return raw;
    }

    // ES256 JWS; the Keystore signs in DER, JOSE wants raw R||S
    static String jws(PrivateKey key, JSONObject claims) throws GeneralSecurityException {
        String input = encodeUrl(bytes("{\"alg\":\"ES256\"}")) + "." + encodeUrl(bytes(claims.toString()));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(key);
        s.update(bytes(input));
        return input + "." + encodeUrl(rawSignature(s.sign()));
    }

    static byte[] encrypt(SecretKey key, byte[] plain) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain);
        return ByteBuffer.allocate(2 + iv.length + ct.length).putShort((short) iv.length).put(iv).put(ct).array();
    }

    static byte[] decrypt(SecretKey key, byte[] box) throws GeneralSecurityException {
        int ivLen = ((box[0] & 0xff) << 8) | (box[1] & 0xff);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, box, 2, ivLen));
        return c.doFinal(box, 2 + ivLen, box.length - 2 - ivLen);
    }
}
