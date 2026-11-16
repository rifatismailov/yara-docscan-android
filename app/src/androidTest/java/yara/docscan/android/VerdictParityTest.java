package yara.docscan.android;

import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.ScanResult;

/**
 * Scans the 42 inert test documents of yara-docscan (test-samples/generated) and checks every
 * verdict against docscan-project/ci/expected-verdicts.tsv - the reference of the PC version.
 */
@RunWith(AndroidJUnit4.class)
public class VerdictParityTest {
    private static final String TAG = "VerdictParity";

    @Test
    public void verdictsMatchPcVersion() throws Exception {
        Context app = InstrumentationRegistry.getInstrumentation().getTargetContext();
        AssetManager testAssets = InstrumentationRegistry.getInstrumentation().getContext().getAssets();
        DocScanner scanner = DocScanner.get(app);

        File dir = new File(app.getCacheDir(), "samples");
        dir.mkdirs();

        List<String> failures = new ArrayList<>();
        int checked = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                testAssets.open("expected-verdicts.tsv"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;
                String[] col = line.split("\t");
                String name = col[0];
                String expected = col[1];

                File f = new File(dir, name);
                try (InputStream in = testAssets.open("samples/" + name);
                     OutputStream out = new FileOutputStream(f)) {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                }

                ScanResult res = scanner.scan(f);
                checked++;
                String got = res.verdict.name();
                Log.i(TAG, String.format("%-28s expected %-6s got %-6s %s", name, expected, got, res.findings));
                if (!expected.equals(got)) {
                    failures.add(name + ": expected " + expected + ", got " + got + "  " + res.rawJson);
                }
            }
        }
        assertTrue("no samples checked", checked > 0);
        assertTrue(failures.size() + "/" + checked + " verdicts differ:\n" + String.join("\n", failures),
                failures.isEmpty());
    }
}
