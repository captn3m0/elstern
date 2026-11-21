package in.captnemo.elstern;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Insets;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.Editable;
import android.text.TextWatcher;
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
import java.net.URI;
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
    Button go;
    TextView out;
    int gen;
    String last = "", cid, tid, trans, bti, useCase;
    PrivateKey key;
    byte[] cert;
    SecretKeySpec k;
    JSONArray fields;

    @Override
    protected void onActivityResult(int rq, int rs, Intent d) {
        if (rs == RESULT_OK) in.setText(d.getStringExtra("t"));
    }

    @Override
    public void onWindowFocusChanged(boolean f) {
        super.onWindowFocusChanged(f);
        if (!f || in.getText().length() > 0) return;
        ClipData c = ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).getPrimaryClip();
        if (c == null || c.getItemCount() == 0 || c.getItemAt(0).getText() == null) return;
        String t = c.getItemAt(0).getText().toString().trim();
        if (valid(t) && !t.equals(last)) in.setText(t);
    }

    LinearLayout.LayoutParams lp() {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
        p.topMargin = (int) (16 * getResources().getDisplayMetrics().density);
        return p;
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        int m = (int) (16 * getResources().getDisplayMetrics().density);
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setOnApplyWindowInsetsListener((v, w) -> {
            Insets i = w.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(i.left + m, i.top + m, i.right + m, i.bottom + m);
            return w;
        });
        in = new EditText(this);
        in.setHint("elster-secure://sec?p=...");
        Button scan = new Button(this);
        scan.setText("Scan QR");
        scan.setOnClickListener(v -> startActivityForResult(new Intent(this, Scan.class), 1));
        go = new Button(this);
        go.setEnabled(false);
        go.setText("Enroll / log in");
        out = new TextView(this);
        out.setTextIsSelectable(true);
        in.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void onTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void afterTextChanged(Editable e) {
                check(e.toString().trim());
            }
        });
        go.setOnClickListener(v -> {
            String uri = in.getText().toString().trim();
            go.setEnabled(false);
            Runnable sign = () -> {
                out.setText("...");
                new Thread(() -> {
                    String r;
                    try {
                        r = finish();
                    } catch (Exception e) {
                        r = String.valueOf(e);
                    }
                    String f = r;
                    runOnUiThread(() -> {
                        last = uri;
                        in.setText("");
                        out.setText(f);
                    });
                }).start();
            };
            if (secure()) auth(gen, sign);
            else sign.run();
        });
        l.addView(in);
        l.addView(scan, lp());
        l.addView(go, lp());
        l.addView(out, lp());
        setContentView(l);
        in.setText(getIntent().getDataString());
    }

    // a valid link enables the button once the transaction type is known
    void check(String uri) {
        int g = ++gen;
        go.setEnabled(false);
        go.setText("Enroll / log in");
        if (!valid(uri)) return;
        go.setText("Checking...");
        new Thread(() -> {
            String err = null;
            try {
                prep(uri);
            } catch (Exception e) {
                err = String.valueOf(e);
            }
            String e2 = err;
            runOnUiThread(() -> {
                if (g != gen) return;
                if (e2 != null) {
                    go.setText("Enroll / log in");
                    out.setText(e2);
                    return;
                }
                StringBuilder sb = new StringBuilder();
                for (String[] x : new String[][]{{"benutzername", "Account"}, {"email", "Email"}}) {
                    String v = field(fields, x[0], "");
                    if (!v.isEmpty()) sb.append(x[1]).append(": ").append(v).append('\n');
                }
                if (useCase.equals("addToken")) sb.append("Device: ").append(Build.MODEL);
                out.setText(sb.toString().trim());
                go.setText(useCase.equals("addToken") ? "Enroll" : "Log in");
                go.setEnabled(true);
            });
        }).start();
    }

    static String param(String u, String n) {
        try {
            String q = URI.create(u).getRawQuery();
            if (q != null) for (String kv : q.split("&")) if (kv.startsWith(n + "=")) return kv.substring(n.length() + 1);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return null;
    }

    boolean secure() {
        return ((KeyguardManager) getSystemService(KEYGUARD_SERVICE)).isDeviceSecure();
    }

    // gate signing behind the lock screen; keys created while secure also require it
    void auth(int g, Runnable ok) {
        new BiometricPrompt.Builder(this).setTitle(go.getText())
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL).build()
                .authenticate(new CancellationSignal(), getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                        ok.run();
                    }

                    @Override
                    public void onAuthenticationError(int c, CharSequence m) {
                        out.setText(m);
                        if (g == gen) go.setEnabled(true);
                    }
                });
    }

    static boolean valid(String u) {
        try {
            JSONObject p = new JSONObject(new String(b64(param(u, "p")), StandardCharsets.UTF_8));
            return (u.startsWith("elster-secure://") || u.startsWith(HOST + "elstersecure")) && p.has("bti")
                    && p.getJSONObject("r").getString("b").startsWith(HOST);
        } catch (Exception e) {
            return false;
        }
    }

    synchronized void prep(String uri) throws Exception {
        JSONObject p = new JSONObject(new String(b64(param(uri, "p")), StandardCharsets.UTF_8));
        JSONObject r = p.getJSONObject("r");
        bti = p.getString("bti");
        String base = r.getString("b");
        if (!base.startsWith(HOST)) throw new IOException("untrusted host " + base);

        SharedPreferences sp = getSharedPreferences("s", 0);
        if (!sp.contains("cid")) {
            byte[] t = new byte[62];
            RND.nextBytes(t);
            sp.edit().putString("cid", UUID.randomUUID().toString().toUpperCase())
                    .putString("tid", Base64.getUrlEncoder().withoutPadding().encodeToString(t)).commit();
        }
        cid = sp.getString("cid", "");
        tid = sp.getString("tid", "");

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(ALIAS)) {
            KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder kb = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateSubject(new X500Principal("CN=Android Keystore Key"));
            if (secure()) kb.setUserAuthenticationParameters(30,
                    KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
            g.initialize(kb.build());
            g.generateKeyPair();
        }
        key = (PrivateKey) ks.getKey(ALIAS, null);
        cert = ks.getCertificate(ALIAS).getEncoded();

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
        k = new SecretKeySpec(ka.generateSecret(), 0, 32, "AES");
        trans = base + r.getString("t");

        JSONObject d = trans(trans, k, cid, "GetTransactionDetails", new JSONObject().put("businessTransactionId", bti));
        if (d.has("data")) d = d.getJSONObject("data");
        useCase = d.optString("useCase");
        fields = d.optJSONArray("dataFields");
        if (fields == null) throw new IOException(d.toString());
    }

    synchronized String finish() throws Exception {
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
        return si + "." + e.encodeToString(raw(s.sign()));
    }

    static byte[] raw(byte[] sig) {
        byte[] raw = new byte[64];
        int p = 2;
        for (int i = 0; i < 2; i++) {
            int n = sig[p + 1] & 0xff, skip = Math.max(0, n - 32), c = n - skip;
            System.arraycopy(sig, p + 2 + skip, raw, i * 32 + 32 - c, c);
            p += 2 + n;
        }
        return raw;
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
