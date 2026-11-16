package yara.docscan.android;

import static org.junit.Assert.assertTrue;

import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.ScanResult;

/** Every test document must get the verdict of the PC version - scanned by the sandboxed worker. */
@RunWith(AndroidJUnit4.class)
public class VerdictParityTest {
    private static final String TAG = "VerdictParity";

    @Test
    public void verdictsMatchPcVersion() throws Exception {
        DocScanner scanner = DocScanner.get(Samples.app());
        File dir = new File(Samples.app().getCacheDir(), "samples");
        List<String> failures = new ArrayList<>();
        List<Samples.Row> rows = Samples.expected();
        for (Samples.Row row : rows) {
            ScanResult res = scanner.scan(Samples.copy(row.name, dir));
            String got = res.verdict.name();
            Log.i(TAG, String.format("%-28s expected %-6s got %-6s %s", row.name, row.verdict, got, res.findings));
            if (!row.verdict.equals(got)) {
                failures.add(row.name + ": expected " + row.verdict + ", got " + got + "  " + res.rawJson());
            }
        }
        assertTrue("no samples checked", !rows.isEmpty());
        assertTrue(failures.size() + "/" + rows.size() + " verdicts differ:\n" + String.join("\n", failures),
                failures.isEmpty());
    }
}
