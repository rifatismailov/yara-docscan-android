package yara.docscan.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import yara.docscan.android.scan.CriticalRules;
import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.watch.CriticalQueue;
import yara.docscan.android.watch.ResultLog;
import yara.docscan.android.watch.ScanPipeline;
import yara.docscan.android.watch.WatchFilter;
import yara.docscan.android.watch.WatchSettings;

/** The watcher's Scan-File end to end: macro store, pass 3, -QuarantineGeneral, records. */
@RunWith(AndroidJUnit4.class)
public class PipelineTest {
    private WatchSettings settings;
    private boolean cure, qGeneral;

    @Before
    public void setUp() throws Exception {
        settings = new WatchSettings(Samples.app());
        cure = settings.cure();
        qGeneral = settings.quarantineGeneral();
        settings.setCure(true);
        settings.setQuarantineGeneral(true);
        CriticalRules.install(Samples.app(),
                InstrumentationRegistry.getInstrumentation().getContext().getAssets().open("crit-test.yar"), "crit-test.yar");
        WatchFilter.setCriticalOn(true);
    }

    @After
    public void tearDown() {
        settings.setCure(cure);
        settings.setQuarantineGeneral(qGeneral);
        CriticalRules.remove(Samples.app());
        WatchFilter.setCriticalOn(false);
    }

    /** The last record of the results log for this path. */
    private static JSONObject record(File f) throws Exception {
        List<String> lines = Files.readAllLines(ResultLog.get(Samples.app()).file().toPath(), StandardCharsets.UTF_8);
        for (int i = lines.size() - 1; i >= 0; i--) {
            JSONObject o = new JSONObject(lines.get(i));
            JSONObject d = o.optJSONObject("docfile");
            if (d != null && f.getPath().equals(d.optString("path"))) return o;
        }
        throw new AssertionError("no record for " + f);
    }

    @Test
    public void scanFileLikeThePcWatcher() throws Exception {
        ScanPipeline p = new ScanPipeline(Samples.app());
        File dir = new File(Samples.app().getCacheDir(), "pipeline-" + System.nanoTime());

        // 1. a document with macros: cured, its VBA in the macro store
        File docm = Samples.copy("macro_suspicious.docm", dir);
        p.scanFile(docm, "Created", true);
        JSONObject r1 = record(docm);
        assertEquals("HIGH", r1.getString("verdict"));
        assertEquals("removed:vbaProject.bin", r1.getString("disarm"));
        JSONObject macro = r1.getJSONObject("macro");
        File stored = new File(macro.getString("file"));
        assertTrue(stored.isFile());
        String code = new String(Files.readAllBytes(stored.toPath()), StandardCharsets.UTF_8);
        assertTrue(code.startsWith("' DocScan macro\r\n"));
        assertTrue(code.contains("' sha256: " + r1.getJSONObject("docfile").getString("sha256")));

        // 2. pass 3: a .txt (watched only with pass 3 on) with the critical phrase -> queued
        File txt = new File(dir, "memo.txt");
        try (OutputStream o = new FileOutputStream(txt)) {
            o.write("Наказ. Для службового користування. Текст.".getBytes(StandardCharsets.UTF_8));
        }
        long before = CriticalQueue.get(Samples.app()).file().length();
        p.scanFile(txt, "Created", true);
        JSONObject crit = record(txt).getJSONObject("critical");
        assertTrue(crit.getBoolean("queued"));
        assertEquals("crit_test_grif", crit.getJSONArray("rules").getString(0));
        assertTrue(CriticalQueue.get(Samples.app()).file().length() > before);
        assertFalse("the text must not go into the record", record(txt).toString().contains("службового"));

        // 3. -QuarantineGeneral: a script that vendor rules match (the macro code saved as .vbs)
        File vbs = new File(dir, "dropper.vbs");
        DocScanner.Options o = new DocScanner.Options();
        o.macro = vbs;
        DocScanner.get(Samples.app()).scan(Samples.copy("macro_suspicious.docm", new File(dir, "src")), o);
        assertTrue(vbs.length() > 0);
        p.scanFile(vbs, "Created", true);
        JSONObject r3 = record(vbs);
        assertNotNull(r3.toString(), r3.optJSONArray("yara_file_matches"));
        assertTrue(r3.toString(), r3.getJSONArray("yara_file_matches").length() > 0);
        assertEquals("HIGH", r3.getString("verdict"));
        assertEquals("quarantined", r3.getString("disarm"));
        assertFalse(vbs.exists());
    }
}
