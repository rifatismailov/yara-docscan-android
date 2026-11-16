package yara.docscan.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.res.AssetManager;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import yara.docscan.android.scan.DocScanException;
import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.RulesBundle;
import yara.docscan.android.scan.ScanResult;

/** A rules update with "detection": the worker switches to it, and back to the built-in rules. */
@RunWith(AndroidJUnit4.class)
public class RulesBundleDeviceTest {
    private static final String MARKER = "DOCSCAN-BUNDLE-TEST-7f3a";
    private static final String EXTRA = "import \"docscan\"\n"
            + "rule BUNDLE_TEST_MARKER {\n  meta:\n    severity = \"HIGH\"\n    finding = \"BUNDLE_TEST\"\n"
            + "  strings:\n    $m = \"" + MARKER + "\"\n  condition:\n    $m\n}\n";

    @After
    public void tearDown() {
        RulesBundle.remove(Samples.app());
    }

    /** The app's own rules tree (assets/rules) + one extra policy rule, as one detection set. */
    private static byte[] detectionBundle(String version) throws Exception {
        AssetManager am = Samples.app().getAssets();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bo)) {
            z.putNextEntry(new ZipEntry("manifest.json"));
            z.write(("{\"version\":\"" + version + "\",\"detection\":[\"detection/docscan-index.yar\",\"extra/marker.yar\"]}")
                    .getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            addTree(am, "rules", "detection", z);
            z.putNextEntry(new ZipEntry("extra/marker.yar"));
            z.write(EXTRA.getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        return bo.toByteArray();
    }

    private static void addTree(AssetManager am, String asset, String name, ZipOutputStream z) throws Exception {
        String[] kids = am.list(asset);
        if (kids == null || kids.length == 0) {
            z.putNextEntry(new ZipEntry(name));
            try (InputStream in = am.open(asset)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) z.write(buf, 0, n);
            }
            z.closeEntry();
            return;
        }
        for (String k : kids) addTree(am, asset + "/" + k, name + "/" + k, z);
    }

    @Test
    public void detectionUpdateIsUsedAndRemovable() throws Exception {
        File f = new File(Samples.app().getCacheDir(), "marker.txt");
        try (OutputStream o = new FileOutputStream(f)) {
            o.write(("hello " + MARKER + " world").getBytes(StandardCharsets.UTF_8));
        }
        DocScanner s = DocScanner.get(Samples.app());
        assertFalse(s.scan(f).findings.contains("BUNDLE_TEST"));   // built-in rules

        RulesBundle.Info i = RulesBundle.install(Samples.app(), new ByteArrayInputStream(detectionBundle("det-1")), "test", null);
        assertEquals("det-1", i.manifest.version);
        assertNotNull(RulesBundle.detectionRules(Samples.app()));
        ScanResult r = s.scan(f);
        assertTrue(r.rawJson(), r.findings.contains("BUNDLE_TEST"));
        assertEquals(ScanResult.Verdict.HIGH, r.verdict);
        // the policy of the updated set still works on real samples
        assertEquals(ScanResult.Verdict.HIGH, s.scan(Samples.copy("macro_suspicious.docm",
                new File(Samples.app().getCacheDir(), "bundle"))).verdict);

        RulesBundle.remove(Samples.app());
        assertNull(RulesBundle.detectionRules(Samples.app()));
        assertFalse(s.scan(f).findings.contains("BUNDLE_TEST"));   // back to the built-in rules
    }

    @Test
    public void brokenUpdateKeepsThePreviousRules() throws Exception {
        Samples.installCriticalBundle("crit-test.yar");
        byte[] bad;
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bo)) {
            z.putNextEntry(new ZipEntry("manifest.json"));
            z.write("{\"version\":\"bad\",\"critical_information\":\"critical/x.yar\"}".getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("critical/x.yar"));
            z.write("rule broken { condition: nosuchthing }".getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        bad = bo.toByteArray();
        try {
            RulesBundle.install(Samples.app(), new ByteArrayInputStream(bad), "test", null);
            fail("a rule set that does not compile was installed");
        } catch (DocScanException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("critical_information"));
        }
        assertEquals("test-crit-test.yar", RulesBundle.info(Samples.app()).manifest.version);
        assertNotNull(RulesBundle.criticalRules(Samples.app()));
    }
}
