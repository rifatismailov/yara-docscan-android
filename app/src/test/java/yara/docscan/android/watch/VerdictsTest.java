package yara.docscan.android.watch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Collections;

import yara.docscan.android.apk.ApkFacts;
import yara.docscan.android.apk.ApkInspector;
import yara.docscan.android.scan.ScanResult;

/** The verdict merging rules of Scan-File in docscan-watcher.ps1, plus the Android package rules. */
public class VerdictsTest {
    private static ScanResult r(String json) {
        return ScanResult.parse("f", json, null);
    }

    private static final String CLEAN_DOC =
            "{\"ftype\":\"ooxml\",\"findings\":[],\"verdict\":\"INFO\",\"yara_file_matches\":[],\"details\":[]}";

    @Test
    public void cleanDocumentIsInfo() {
        assertEquals("INFO", Verdicts.merge("document", false, r(CLEAN_DOC), null).verdict);
    }

    @Test
    public void vendorMatchOnDocumentIsAtLeastMedium() {
        ScanResult s = r("{\"ftype\":\"ooxml\",\"verdict\":\"INFO\",\"yara_file_matches\":[],"
                + "\"yara_matches\":[\"VBA_Rule\"],\"details\":[]}");
        Verdicts.Merged m = Verdicts.merge("document", false, s, null);
        assertEquals("MEDIUM", m.verdict);
        assertEquals(Collections.singletonList("VBA_Rule"), m.yaraFileMatches);
    }

    @Test
    public void vendorMatchOnGeneralFileIsHigh() {
        ScanResult s = r("{\"ftype\":\"unknown\",\"verdict\":\"INFO\",\"yara_file_matches\":[\"Mimikatz\"],\"details\":[]}");
        assertEquals("HIGH", Verdicts.merge("general", false, s, null).verdict);
    }

    @Test
    public void docMatchesCountOnlyForDocumentsAndArchives() {
        String j = "{\"ftype\":\"unknown\",\"verdict\":\"INFO\",\"yara_file_matches\":[],"
                + "\"yara_doc_matches\":[\"Shellcode\"],\"details\":[]}";
        assertEquals("INFO", Verdicts.merge("general", false, r(j), null).verdict);
        assertEquals("HIGH", Verdicts.merge("general", true, r(j), null).verdict);
        assertEquals("MEDIUM", Verdicts.merge("document", false, r(j), null).verdict);
    }

    @Test
    public void zipUnderAnotherNameWithInnerMatchIsMedium() {
        ScanResult s = r("{\"ftype\":\"zip\",\"verdict\":\"INFO\",\"yara_file_matches\":[],"
                + "\"yara_part_matches\":[{\"part\":\"x.exe\",\"rules\":[\"Miner\"]}],\"details\":[]}");
        Verdicts.Merged m = Verdicts.merge("general", false, s, null);
        assertEquals("MEDIUM", m.verdict);
        assertTrue(m.yaraFileMatches.contains("Miner"));
    }

    @Test
    public void apkIgnoresArchivePolicy() {
        // Cordova app: .js assets fire DS_ARCHIVE_SCRIPT (HIGH) - meaningless for a package
        ScanResult s = r("{\"ftype\":\"zip\",\"verdict\":\"HIGH\",\"findings\":[\"ARCHIVE_SCRIPT\"],"
                + "\"yara_file_matches\":[],\"archive_entries\":[\"AndroidManifest.xml\",\"classes.dex\",\"assets/www/app.js\"],"
                + "\"details\":[{\"rule\":\"DS_ARCHIVE_SCRIPT\",\"finding\":\"ARCHIVE_SCRIPT\",\"severity\":\"HIGH\"}]}");
        ApkFacts f = new ApkFacts();
        f.parsed = true;
        Verdicts.Merged m = Verdicts.merge("apk", false, s, ApkInspector.inspect(f));
        assertEquals("INFO", m.verdict);
        assertTrue(m.apk);
    }

    @Test
    public void apkWithDexVendorMatchIsHigh() {
        ScanResult s = ScanResult.parse("a.apk",
                "{\"ftype\":\"zip\",\"verdict\":\"INFO\",\"yara_file_matches\":[],"
                        + "\"archive_entries\":[\"AndroidManifest.xml\",\"classes.dex\"],\"details\":[]}",
                "{\"dex\":[{\"part\":\"classes.dex\",\"rules\":[\"Android_SpyNote\"]}],\"descriptions\":[]}");
        Verdicts.Merged m = Verdicts.merge("apk", false, s, null);
        assertEquals("HIGH", m.verdict);
        assertTrue(Verdicts.summary(s, m, null, null).contains("YARA Android_SpyNote (in classes.dex)"));
    }

    @Test
    public void apkInsideArchiveIsMedium() {
        ScanResult s = r("{\"ftype\":\"zip\",\"verdict\":\"INFO\",\"yara_file_matches\":[],"
                + "\"archive_entries\":[\"readme.txt\",\"Bank.apk\"],\"details\":[]}");
        Verdicts.Merged m = Verdicts.merge("general", true, s, null);
        assertEquals("MEDIUM", m.verdict);
        assertEquals("APK_IN_ARCHIVE", m.androidFindings.get(0).finding);
    }

    @Test
    public void workerCrashIsError() {
        ScanResult s = ScanResult.error("x.docx", "parser crashed");
        assertEquals("ERROR", Verdicts.merge("document", false, s, null).verdict);
    }

    @Test
    public void summaryLikeGetSummary() {
        ScanResult s = r("{\"ftype\":\"ooxml\",\"verdict\":\"HIGH\",\"findings_text\":[\"Макрос\"],"
                + "\"yara_file_matches\":[],\"yara_matches\":[\"VBA_Download\"],"
                + "\"yara_descriptions\":[{\"rule\":\"VBA_Download\",\"description\":\"downloader\"}],\"details\":[]}");
        Verdicts.Merged m = Verdicts.merge("document", false, s, null);
        assertEquals("Макрос | YARA VBA_Download (in macro code) - downloader | action: removed:vbaProject.bin",
                Verdicts.summary(s, m, "removed:vbaProject.bin", null));
    }

    @Test
    public void matchesInsidePackageAssetsDoNotRaiseVerdict() {
        ScanResult s = r("{\"ftype\":\"zip\",\"verdict\":\"INFO\",\"yara_file_matches\":[],"
                + "\"archive_entries\":[\"AndroidManifest.xml\",\"classes.dex\",\"assets/data01.zip\"],"
                + "\"yara_part_matches\":[{\"part\":\"archive:assets/data01.zip\",\"rules\":[\"maldoc_x\"]}],\"details\":[]}");
        Verdicts.Merged m = Verdicts.merge("apk", false, s, null);
        assertEquals("INFO", m.verdict);
        assertTrue(m.yaraFileMatches.contains("maldoc_x"));
    }
}
