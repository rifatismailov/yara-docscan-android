package yara.docscan.android.scan;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** manifest.json and the unpacking of a rules update (no compilation here: that needs the device). */
public class RulesBundleTest {
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final String RULE = "rule crit { strings: $a = \"x\" condition: $a }\n";

    private static byte[] zip(String... nameThenBody) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bo)) {
            for (int i = 0; i < nameThenBody.length; i += 2) {
                z.putNextEntry(new ZipEntry(nameThenBody[i]));
                z.write(nameThenBody[i + 1].getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return bo.toByteArray();
    }

    private static String sha(String s) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void expectFail(byte[] zip, String message) throws Exception {
        try {
            RulesBundle.extract(new ByteArrayInputStream(zip), tmp.newFolder());
            fail("accepted: " + message);
        } catch (DocScanException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(message));
        }
    }

    @Test
    public void parsesStringOrListAndChunk() throws Exception {
        RulesBundle.Manifest m = RulesBundle.parseManifest("{\"version\":\"1\",\"critical_information\":\"critical/a.yar\","
                + "\"detection\":[\"d/index.yar\"],\"critical_chunk\":{\"size\":800,\"overlap\":100}}");
        assertEquals("1", m.version);
        assertEquals("critical/a.yar", m.critical.get(0));
        assertEquals("d/index.yar", m.detection.get(0));
        assertEquals(800, m.chunkSize);
        assertEquals(100, m.chunkOverlap);
        m = RulesBundle.parseManifest("{\"version\":\"2\",\"critical_information\":[\"c/a.yar\",\"c/b.yar\"]}");
        assertEquals(2, m.critical.size());
        assertTrue(m.detection.isEmpty());
        assertEquals(-1, m.chunkOverlap);
    }

    @Test
    public void rejectsBadManifests() {
        for (String[] c : new String[][] {
                {"{\"critical_information\":\"a.yar\"}", "version"},
                {"{\"version\":\"1\"}", "neither"},
                {"{\"version\":\"1\",\"critical_information\":\"../a.yar\"}", "bad path"},
                {"{\"version\":\"1\",\"critical_information\":\"/etc/a.yar\"}", "bad path"},
                {"{\"version\":\"1\",\"critical_information\":5}", "path or a list"},
                {"{\"version\":\"1\",\"critical_information\":\"a.yar\",\"critical_chunk\":{\"size\":100,\"overlap\":0}}", "critical_chunk"},
                {"not json", "bad manifest"}}) {
            try {
                RulesBundle.parseManifest(c[0]);
                fail("accepted " + c[0]);
            } catch (DocScanException e) {
                assertTrue(c[0] + " -> " + e.getMessage(), e.getMessage().contains(c[1]));
            }
        }
    }

    @Test
    public void extractsAndChecksHashes() throws Exception {
        File dir = tmp.newFolder();
        byte[] z = zip("manifest.json", "{\"version\":\"7\",\"critical_information\":\"critical/r.yar\","
                + "\"files\":{\"critical/r.yar\":\"" + sha(RULE) + "\"}}", "critical/r.yar", RULE);
        RulesBundle.Manifest m = RulesBundle.extract(new ByteArrayInputStream(z), dir);
        assertEquals("7", m.version);
        assertTrue(new File(dir, "critical/r.yar").isFile());
    }

    @Test
    public void rejectsBadArchives() throws Exception {
        expectFail(zip("critical/r.yar", RULE), "no manifest.json");
        expectFail(zip("manifest.json", "{\"version\":\"1\",\"critical_information\":\"critical/r.yar\"}"),
                "missing file");
        expectFail(zip("manifest.json", "{\"version\":\"1\",\"critical_information\":\"critical/r.yar\","
                + "\"files\":{\"critical/r.yar\":\"" + sha("other") + "\"}}", "critical/r.yar", RULE), "sha256 mismatch");
        expectFail(zip("manifest.json", "{\"version\":\"1\",\"critical_information\":\"r.yar\"}",
                "../../evil.yar", RULE, "r.yar", RULE), "bad path");   // zip slip
    }
}
