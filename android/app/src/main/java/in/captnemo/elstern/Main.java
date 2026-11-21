package in.captnemo.elstern;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Insets;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class Main extends Activity {
    static final int TOKEN_TYPE = 80010003;
    static final String ALIAS = "elstern";
    static final String HOST = "https://www.elster.de/";
    static final SecureRandom RND = new SecureRandom();

    EditText in;

    @Override
    protected void onActivityResult(int rq, int rs, Intent d) {
        if (rs == RESULT_OK) in.setText(d.getStringExtra("t"));
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setOnApplyWindowInsetsListener((v, w) -> {
            Insets i = w.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(i.left + 32, i.top + 32, i.right + 32, i.bottom + 32);
            return w;
        });
        in = new EditText(this);
        in.setHint("elster-secure://sec?p=...");
        in.setText(getIntent().getDataString());
        Button scan = new Button(this);
        scan.setText("Scan QR");
        scan.setOnClickListener(v -> startActivityForResult(new Intent(this, Scan.class), 1));
        Button go = new Button(this);
        go.setText("Enroll / log in");
        TextView out = new TextView(this);
        out.setTextIsSelectable(true);
        go.setOnClickListener(v -> {
            String uri = in.getText().toString().trim();
            out.setText("...");
            new Thread(() -> {
                String r;
                try {
                    r = run(uri);
                } catch (Exception e) {
                    r = String.valueOf(e);
                }
                String f = r;
                runOnUiThread(() -> out.setText(f));
            }).start();
        });
        l.addView(in);
        l.addView(scan);
        l.addView(go);
        l.addView(out);
        setContentView(l);
    }

    String run(String uri) throws Exception {
        JSONObject p = new JSONObject(new String(b64(Uri.parse(uri).getQueryParameter("p")), StandardCharsets.UTF_8));
        JSONObject r = p.getJSONObject("r");
        String bti = p.getString("bti"), base = r.getString("b");
        if (!base.startsWith(HOST)) throw new IOException("untrusted host " + base);

        SharedPreferences sp = getSharedPreferences("s", 0);
        if (!sp.contains("cid")) {
            byte[] t = new byte[62];
            RND.nextBytes(t);
            sp.edit().putString("cid", UUID.randomUUID().toString().toUpperCase())
                    .putString("tid", Base64.getUrlEncoder().withoutPadding().encodeToString(t)).commit();
        }
        String cid = sp.getString("cid", ""), tid = sp.getString("tid", "");

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(ALIAS)) {
            KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            g.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateSubject(new X500Principal("CN=Android Keystore Key")).build());
            g.generateKeyPair();
        }
        PrivateKey key = (PrivateKey) ks.getKey(ALIAS, null);
        byte[] cert = ks.getCertificate(ALIAS).getEncoded();

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair kp = g.generateKeyPair();
        JSONObject boot = post(base + r.getString("p0"), new JSONObject()
                .put("clientId", cid)
                .put("clientPlatform", new JSONObject().put("deviceName", Build.MODEL).put("osName", "Android")
                        .put("osVersion", Build.VERSION.RELEASE).put("platformName", "Android"))
                .put("clientVersion", "1.11.1")
                .put("publicKey", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded())));
        JSONObject pl = new JSONObject(new String(b64(boot.getString("signedJwt").split("\\.")[1]), StandardCharsets.UTF_8));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(b64(pl.getString("B")))), true);
        SecretKeySpec k = new SecretKeySpec(ka.generateSecret(), 0, 32, "AES");
        String trans = base + r.getString("t");

        JSONObject d = trans(trans, k, cid, "GetTransactionDetails", new JSONObject().put("businessTransactionId", bti));
        if (d.has("data")) d = d.getJSONObject("data");
        String useCase = d.optString("useCase");
        JSONArray fields = d.optJSONArray("dataFields");
        if (fields == null) return d.toString();
        long iat = System.currentTimeMillis() / 1000;
        JSONObject sig = new JSONObject().put("tokenId", tid).put("tokenType", String.valueOf(TOKEN_TYPE));
        JSONObject resp;
        if (useCase.equals("addToken")) {
            for (int i = 0; i < fields.length(); i++) {
                JSONObject f = fields.getJSONObject(i);
                if (f.optString("name").equals("nameMobilesGeraet")) f.put("value", Build.MODEL);
            }
            byte[] t = tid.getBytes(StandardCharsets.US_ASCII);
            byte[] cont = der(0x30, der(2, new byte[]{1}), der(0xA0, der(4, cert)));
            String enc = Base64.getEncoder().encodeToString(ByteBuffer.allocate(10 + t.length + 4 + cont.length)
                    .putShort((short) 3).putInt(TOKEN_TYPE).put(new byte[3]).put((byte) 'S').put(t)
                    .putInt(cont.length).put(cont).array());
            JSONObject inner = new JSONObject().put("dataFields", fields)
                    .put("newToken", new JSONObject().put("encodedToken", enc).put("tokenId", tid).put("tokenType", TOKEN_TYPE))
                    .put("signatureToken", sig);
            resp = trans(trans, k, cid, "AddToken", new JSONObject().put("businessTransactionId", bti)
                    .put("clientName", "<NOT SET>").put("signedJWT", jws(key, iat, inner, useCase)));
        } else {
            JSONArray out = new JSONArray();
            String csr = field(fields, "pkcs10Request", "");
            if (!csr.isEmpty()) out.put(fld("pkcs10Request", "_hidden_", csr));
            out.put(fld("initApp", "_hidden_", field(fields, "initApp", "")))
                    .put(fld("sessionTicket", "_hidden_", field(fields, "sessionTicket", "")))
                    .put(fld("loginTokenGueltigkeit", "_hidden_", field(fields, "loginTokenGueltigkeit", "86400")))
                    .put(fld("_challenge_", "_meta_", field(fields, "_challenge_", "")))
                    .put(fld("_transactionQueryTime_", "_meta_", String.valueOf(System.currentTimeMillis())));
            resp = trans(trans, k, cid, "Auth", new JSONObject().put("businessTransactionId", bti)
                    .put("signedJWT", jws(key, iat, new JSONObject().put("dataFields", out).put("signatureToken", sig), useCase)));
        }
        JSONObject n = resp.optJSONObject("resultNotificationByClient");
        if (n == null) return resp.toString();
        StringBuilder sb = new StringBuilder(useCase).append(":\n");
        JSONArray a = n.optJSONArray("dataFields");
        for (int i = 0; a != null && i < a.length(); i++) sb.append(a.getJSONObject(i).optString("label")).append('\n');
        return sb.toString().trim();
    }

    static JSONObject fld(String name, String type, String value) throws Exception {
        return new JSONObject().put("name", name).put("type", type).put("value", value);
    }

    static String field(JSONArray a, String name, String def) {
        for (int i = 0; i < a.length(); i++) {
            JSONObject f = a.optJSONObject(i);
            if (f != null && name.equals(f.optString("name"))) return f.optString("value", def);
        }
        return def;
    }

    static byte[] b64(String s) {
        return Base64.getUrlDecoder().decode(s.trim().replace('+', '-').replace('/', '_'));
    }

    static byte[] der(int tag, byte[]... parts) {
        ByteArrayOutputStream v = new ByteArrayOutputStream();
        for (byte[] p : parts) v.writeBytes(p);
        int n = v.size();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(tag);
        if (n < 128) {
            o.write(n);
        } else {
            o.write(0x82);
            o.write(n >> 8);
            o.write(n);
        }
        o.writeBytes(v.toByteArray());
        return o.toByteArray();
    }

    // ES256 JWT; Keystore returns DER signatures, JOSE wants raw R||S
    static String jws(PrivateKey key, long iat, JSONObject inner, String useCase) throws Exception {
        Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();
        String si = e.encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + e.encodeToString(new JSONObject().put("exp", iat + 120).put("iat", iat)
                .put("payload", inner.toString()).put("useCase", useCase).toString().getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(key);
        s.update(si.getBytes(StandardCharsets.US_ASCII));
        byte[] der = s.sign(), raw = new byte[64];
        int p = 2;
        for (int i = 0; i < 2; i++) {
            int n = der[p + 1] & 0xff, skip = Math.max(0, n - 32), c = n - skip;
            System.arraycopy(der, p + 2 + skip, raw, i * 32 + 32 - c, c);
            p += 2 + n;
        }
        return si + "." + e.encodeToString(raw);
    }

    static JSONObject trans(String url, SecretKeySpec k, String cid, String type, JSONObject plain) throws Exception {
        byte[] iv = new byte[12];
        RND.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain.toString().getBytes(StandardCharsets.UTF_8));
        byte[] body = ByteBuffer.allocate(14 + ct.length).putShort((short) 12).put(iv).put(ct).array();
        JSONObject r = post(url, new JSONObject().put("payload", Base64.getEncoder().encodeToString(body))
                .put("requestType", type).put("senderId", cid));
        if (!r.optBoolean("success")) return r;
        byte[] raw = b64(r.getString("payload"));
        int n = ((raw[0] & 0xff) << 8) | (raw[1] & 0xff);
        c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, raw, 2, n));
        return new JSONObject(new String(c.doFinal(raw, 2 + n, raw.length - 2 - n), StandardCharsets.UTF_8));
    }

    static JSONObject post(String url, JSONObject o) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setDoOutput(true);
        c.setConnectTimeout(30000);
        c.setReadTimeout(30000);
        c.setRequestProperty("Content-Type", "application/json");
        c.setRequestProperty("Accept", "application/json");
        try (OutputStream s = c.getOutputStream()) {
            s.write(o.toString().getBytes(StandardCharsets.UTF_8));
        }
        int code = c.getResponseCode();
        String body = new String((code < 400 ? c.getInputStream() : c.getErrorStream()).readAllBytes(), StandardCharsets.UTF_8);
        if (code >= 400) throw new IOException(url + " HTTP " + code + ": " + body);
        return new JSONObject(body);
    }
}
