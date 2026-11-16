package yara.docscan.android;

import static org.junit.Assert.assertTrue;

import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import yara.docscan.android.scan.Disarm;
import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.Quarantine;
import yara.docscan.android.scan.ScanResult;

/**
 * Cure every test document the way the watcher does (plan in the sandboxed worker, apply in the app)
 * and compare with the PC version: the disarm action ("removed", "stripped", "quarantined", "deleted",
 * "detect-only" or "-" for none) and the verdict of the cured file ("DELETED" = the file is gone).
 */
@RunWith(AndroidJUnit4.class)
public class DisarmParityTest {
    private static final String TAG = "DisarmParity";

    @Test
    public void disarmMatchesPcVersion() throws Exception {
        DocScanner scanner = DocScanner.get(Samples.app());
        File dir = new File(Samples.app().getCacheDir(), "disarm");
        File cured = new File(Samples.app().getCacheDir(), "cured.tmp");
        Quarantine q = new Quarantine(Samples.app());
        List<String> failures = new ArrayList<>();
        List<Samples.Row> rows = Samples.expected();
        for (Samples.Row row : rows) {
            File f = Samples.copy(row.name, dir);
            ScanResult r = scanner.scan(f, true, cured);
            String action = Disarm.apply(f, r, cured, q, "test");
            String after;
            if (!f.exists()) {
                after = "DELETED";
            } else {
                after = scanner.scan(f).verdict.name();
            }
            boolean actionOk = row.disarm.equals("-") ? action == null
                    : action != null && action.startsWith(row.disarm);
            boolean afterOk = row.after.equals(after);
            Log.i(TAG, String.format("%-28s disarm %-12s got %-28s after %-7s got %s",
                    row.name, row.disarm, action, row.after, after));
            if (!actionOk || !afterOk) {
                failures.add(row.name + ": disarm " + row.disarm + " / got " + action
                        + ", after " + row.after + " / got " + after);
            }
        }
        cured.delete();
        assertTrue(failures.size() + "/" + rows.size() + " differ:\n" + String.join("\n", failures),
                failures.isEmpty());
    }
}
