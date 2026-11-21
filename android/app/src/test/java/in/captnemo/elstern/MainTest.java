package in.captnemo.elstern;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class MainTest {
    static String link(String scheme, String base) {
        String json = "{\"s\":\"x\",\"c\":\"y\",\"v\":\"2.1\",\"bti\":\"abc\",\"r\":{\"b\":\"" + base
                + "\",\"t\":\"/t\",\"p\":\"/p\",\"p0\":\"/p0\",\"u\":\"/u\"}}";
        return scheme + "?p=" + Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void validLinks() {
        assertTrue(Main.valid(link("elster-secure://sec", "https://www.elster.de/spro4u")));
        assertTrue(Main.valid(link("https://www.elster.de/elstersecure", "https://www.elster.de/spro4u") + "&initApp=Mein%20ELSTER"));
    }

    @Test
    public void invalidLinks() {
        assertFalse(Main.valid(link("elster-secure://sec", "https://evil.example/spro4u")));
        assertFalse(Main.valid(link("http://www.elster.de/elstersecure", "https://www.elster.de/spro4u")));
        assertFalse(Main.valid(link("https://evil.example/elstersecure", "https://www.elster.de/spro4u")));
        assertFalse(Main.valid("elster-secure://sec"));
        assertFalse(Main.valid("elster-secure://sec?p=!!!"));
        assertFalse(Main.valid("not a link"));
        assertFalse(Main.valid(""));
    }

    @Test
    public void derShortAndLong() {
        assertArrayEquals(new byte[]{4, 2, 1, 2}, Main.der(4, new byte[]{1, 2}));
        byte[] d = Main.der(0x30, new byte[300]);
        assertArrayEquals(new byte[]{0x30, (byte) 0x82, 0x01, 0x2C}, Arrays.copyOf(d, 4));
        assertEquals(304, d.length);
    }

    @Test
    public void derConcatenatesParts() {
        assertArrayEquals(new byte[]{0x30, 5, 2, 1, 1, 5, 0}, Main.der(0x30, Main.der(2, new byte[]{1}), Main.der(5)));
    }

    @Test
    public void rawSignatureStripsPaddingAndPads() {
        byte[] r = new byte[33], s = new byte[31];
        Arrays.fill(r, (byte) 0x11);
        r[0] = 0;
        r[1] = (byte) 0x80;
        Arrays.fill(s, (byte) 0x22);
        byte[] der = Main.der(0x30, Main.der(2, r), Main.der(2, s));
        byte[] raw = Main.raw(der);
        assertEquals(64, raw.length);
        assertEquals((byte) 0x80, raw[0]);
        assertEquals((byte) 0x11, raw[31]);
        assertEquals(0, raw[32]);
        assertEquals((byte) 0x22, raw[33]);
        assertEquals((byte) 0x22, raw[63]);
    }

    @Test
    public void b64AcceptsUrlAndStandard() {
        assertArrayEquals(new byte[]{(byte) 0xfb, (byte) 0xff}, Main.b64("-_8"));
        assertArrayEquals(new byte[]{(byte) 0xfb, (byte) 0xff}, Main.b64("+/8="));
    }
}
