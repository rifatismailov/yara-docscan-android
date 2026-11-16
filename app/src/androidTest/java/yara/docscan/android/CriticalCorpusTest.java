package yara.docscan.android;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import android.content.res.AssetManager;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.RulesBundle;
import yara.docscan.android.scan.ScanResult;

/**
 * Pass 3 on a document corpus against the PC yara, file by file: queued or not, the matched rules,
 * fragment count, total chars and the fragments themselves (hash). Needs the corpus, which is not in
 * the repository:
 *
 *   python3 tools/critical_reference.py <PC yara> <rules.yar> <docs> critical-expected.tsv
 *   ./gradlew connectedDebugAndroidTest -PcriticalCorpus=<docs> -PcriticalRules=<rules.yar> \
 *       -PcriticalExpected=critical-expected.tsv
 *
 * Skipped without them.
 */
@RunWith(AndroidJUnit4.class)
public class CriticalCorpusTest {
    private static final String TAG = "CriticalCorpus";

    @After
    public void tearDown() {
        RulesBundle.remove(Samples.app());
    }

    @Test
    public void passThreeMatchesPcVersion() throws Exception {
        AssetManager am = InstrumentationRegistry.getInstrumentation().getContext().getAssets();
        String[] top = am.list("critical-corpus");
        assumeTrue("no corpus (-PcriticalCorpus ...)", top != null && top.length > 0);
        String rules = null;
        for (String n : top) if (n.endsWith(".yar") || n.endsWith(".yara")) rules = n;
        assumeTrue(rules != null);
        Samples.installCriticalBundle("critical-corpus/" + rules);
        DocScanner scanner = DocScanner.get(Samples.app());
        File dir = new File(Samples.app().getCacheDir(), "corpus");

        List<String> failures = new ArrayList<>();
        int rows = 0, queued = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                am.open("critical-corpus/critical-expected.tsv"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#") || line.isEmpty()) continue;
                String[] c = line.split("\t", -1);
                String name = c[0], want = c[1];
                File f = Samples.copyAsset("critical-corpus/docs/" + name, new File(dir, name));
                DocScanner.Options o = new DocScanner.Options();
                o.critical = new File(dir, "line.tmp");
                ScanResult res = scanner.scan(f, o);
                String got = res.critical == null ? "none" : res.critical.optString("status");
                rows++;
                String detail = "";
                if ("queued".equals(got)) {
                    queued++;
                    JSONObject q = new JSONObject(new String(Files.readAllBytes(o.critical.toPath()), StandardCharsets.UTF_8).trim());
                    JSONArray m = q.getJSONObject("metadata").getJSONArray("yara_matches");
                    List<String> ms = new ArrayList<>();
                    for (int i = 0; i < m.length(); i++) ms.add(m.getString(i));
                    JSONObject ti = q.getJSONObject("text_info");
                    String gotRow = String.join(",", ms) + "\t" + ti.getInt("fragment_count") + "\t"
                            + ti.getInt("total_chars") + "\t" + fragmentsHash(q.getJSONArray("fragments"));
                    String wantRow = c[2] + "\t" + c[3] + "\t" + c[4] + "\t" + c[5];
                    if (!gotRow.equals(wantRow)) detail = " | want " + wantRow + " got " + gotRow;
                }
                if (!want.equals(got) || !detail.isEmpty()) failures.add(name + ": want " + want + " got " + got + detail);
                f.delete();
            }
        }
        Log.i(TAG, rows + " documents, " + queued + " queued, " + failures.size() + " differ");
        assertTrue(failures.size() + "/" + rows + " differ from the PC version:\n"
                + String.join("\n", failures.subList(0, Math.min(40, failures.size()))), failures.isEmpty());
    }

    /** sha256 of "start:end:text\n" per fragment, first 16 hex (tools/critical_reference.py). */
    static String fragmentsHash(JSONArray fr) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < fr.length(); i++) {
            JSONObject f = fr.getJSONObject(i);
            md.update((f.getInt("start") + ":" + f.getInt("end") + ":" + f.getString("text") + "\n")
                    .getBytes(StandardCharsets.UTF_8));
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) sb.append(String.format("%02x", b));
        return sb.substring(0, 16);
    }
}
