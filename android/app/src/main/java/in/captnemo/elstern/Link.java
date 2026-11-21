package in.captnemo.elstern;

import org.json.JSONObject;

import java.net.URI;

final class Link {
    static final String HOST = "https://www.elster.de/";

    final String bti, base, bootstrap, transaction;

    private Link(JSONObject p) throws Exception {
        JSONObject r = p.getJSONObject("r");
        bti = p.getString("bti");
        base = r.getString("b");
        bootstrap = base + r.getString("p0");
        transaction = base + r.getString("t");
    }

    // null unless it is an ELSTER Secure link whose endpoints live on HOST
    static Link parse(String uri) {
        if (uri == null || !(uri.startsWith("elster-secure://") || uri.startsWith(HOST + "elstersecure"))) return null;
        try {
            Link link = new Link(new JSONObject(Codec.text(Codec.decode(query(uri, "p")))));
            return link.base.startsWith(HOST) ? link : null;
        } catch (Exception e) {
            return null;
        }
    }

    static String query(String uri, String name) {
        String q = URI.create(uri).getRawQuery();
        if (q == null) return null;
        for (String kv : q.split("&")) {
            if (kv.startsWith(name + "=")) return kv.substring(name.length() + 1);
        }
        return null;
    }
}
