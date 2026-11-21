package in.captnemo.elstern;

import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// One ELSTER Secure transaction: handshake and fetch details, then enroll or log in
final class Elster {
    static final int TOKEN_TYPE = 80010003;
    static final String CLIENT_VERSION = "1.11.1";

    final String useCase;
    final JSONArray fields;
    private final Link link;
    private final Device device;
    private final SecretKey key;

    Elster(Link link, Device device) throws Exception {
        this.link = link;
        this.device = device;
        key = handshake();
        JSONObject details = request("GetTransactionDetails", new JSONObject().put("businessTransactionId", link.bti));
        if (details.has("data")) details = details.getJSONObject("data");
        useCase = details.optString("useCase");
        fields = details.optJSONArray("dataFields");
        if (fields == null) throw new IOException(details.toString());
    }

    boolean enrolling() {
        return useCase.equals("addToken");
    }

    String field(String name, String fallback) {
        for (int i = 0; i < fields.length(); i++) {
            JSONObject f = fields.optJSONObject(i);
            if (f != null && name.equals(f.optString("name"))) return f.optString("value", fallback);
        }
        return fallback;
    }

    String confirm() throws Exception {
        JSONObject resp = enrolling() ? addToken() : logIn();
        JSONObject note = resp.optJSONObject("resultNotificationByClient");
        if (note == null) return resp.toString();
        StringBuilder sb = new StringBuilder(useCase).append(":\n");
        JSONArray labels = note.optJSONArray("dataFields");
        for (int i = 0; labels != null && i < labels.length(); i++) {
            sb.append(labels.getJSONObject(i).optString("label")).append('\n');
        }
        return sb.toString().trim();
    }

    private SecretKey handshake() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair ours = g.generateKeyPair();
        JSONObject platform = new JSONObject().put("deviceName", Build.MODEL).put("osName", "Android")
                .put("osVersion", Build.VERSION.RELEASE).put("platformName", "Android");
        JSONObject resp = post(link.bootstrap, new JSONObject()
                .put("clientId", device.clientId)
                .put("clientPlatform", platform)
                .put("clientVersion", CLIENT_VERSION)
                .put("publicKey", Codec.encode(ours.getPublic().getEncoded())));
        JSONObject jwt = new JSONObject(Codec.text(Codec.decode(resp.getString("signedJwt").split("\\.")[1])));
        PublicKey theirs = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(Codec.decode(jwt.getString("B"))));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ours.getPrivate());
        ka.doPhase(theirs, true);
        return new SecretKeySpec(ka.generateSecret(), 0, 32, "AES");
    }

    private JSONObject addToken() throws Exception {
        for (int i = 0; i < fields.length(); i++) {
            JSONObject f = fields.getJSONObject(i);
            if (f.optString("name").equals("nameMobilesGeraet")) f.put("value", Build.MODEL);
        }
        JSONObject token = new JSONObject().put("encodedToken", Codec.encode(encodedToken()))
                .put("tokenId", device.tokenId).put("tokenType", TOKEN_TYPE);
        JSONObject payload = new JSONObject().put("dataFields", fields).put("newToken", token)
                .put("signatureToken", signatureToken());
        return request("AddToken", new JSONObject().put("businessTransactionId", link.bti)
                .put("clientName", "<NOT SET>").put("signedJWT", sign(payload)));
    }

    private JSONObject logIn() throws Exception {
        JSONArray out = new JSONArray();
        String csr = field("pkcs10Request", "");
        if (!csr.isEmpty()) out.put(dataField("pkcs10Request", "_hidden_", csr));
        out.put(dataField("initApp", "_hidden_", field("initApp", "")))
                .put(dataField("sessionTicket", "_hidden_", field("sessionTicket", "")))
                .put(dataField("loginTokenGueltigkeit", "_hidden_", field("loginTokenGueltigkeit", "86400")))
                .put(dataField("_challenge_", "_meta_", field("_challenge_", "")))
                .put(dataField("_transactionQueryTime_", "_meta_", String.valueOf(System.currentTimeMillis())));
        JSONObject payload = new JSONObject().put("dataFields", out).put("signatureToken", signatureToken());
        return request("Auth", new JSONObject().put("businessTransactionId", link.bti).put("signedJWT", sign(payload)));
    }

    private byte[] encodedToken() {
        byte[] id = device.tokenId.getBytes(StandardCharsets.US_ASCII);
        byte[] blob = Codec.der(0x30, Codec.der(2, new byte[]{1}), Codec.der(0xA0, Codec.der(4, device.cert)));
        return ByteBuffer.allocate(10 + id.length + 4 + blob.length)
                .putShort((short) 3).putInt(TOKEN_TYPE).put(new byte[3]).put((byte) 'S').put(id)
                .putInt(blob.length).put(blob).array();
    }

    private JSONObject signatureToken() throws Exception {
        return new JSONObject().put("tokenId", device.tokenId).put("tokenType", String.valueOf(TOKEN_TYPE));
    }

    private String sign(JSONObject payload) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        return Codec.jws(device.key, new JSONObject().put("exp", now + 120).put("iat", now)
                .put("payload", payload.toString()).put("useCase", useCase));
    }

    static JSONObject dataField(String name, String type, String value) throws Exception {
        return new JSONObject().put("name", name).put("type", type).put("value", value);
    }

    private JSONObject request(String type, JSONObject body) throws Exception {
        JSONObject resp = post(link.transaction, new JSONObject()
                .put("payload", Codec.encode(Codec.encrypt(key, Codec.bytes(body.toString()))))
                .put("requestType", type).put("senderId", device.clientId));
        if (!resp.optBoolean("success")) return resp;
        return new JSONObject(Codec.text(Codec.decrypt(key, Codec.decode(resp.getString("payload")))));
    }

    static JSONObject post(String url, JSONObject body) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setDoOutput(true);
        c.setConnectTimeout(30000);
        c.setReadTimeout(30000);
        c.setRequestProperty("Content-Type", "application/json");
        c.setRequestProperty("Accept", "application/json");
        try (OutputStream s = c.getOutputStream()) {
            s.write(Codec.bytes(body.toString()));
        }
        int code = c.getResponseCode();
        try (InputStream s = code < 400 ? c.getInputStream() : c.getErrorStream()) {
            String text = Codec.text(s.readAllBytes());
            if (code >= 400) throw new IOException(url + " HTTP " + code + ": " + text);
            return new JSONObject(text);
        }
    }
}
