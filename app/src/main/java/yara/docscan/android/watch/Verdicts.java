package yara.docscan.android.watch;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import yara.docscan.android.apk.ApkInspector;
import yara.docscan.android.scan.ScanResult;

/**
 * The watcher-level verdict of a file: the rules of Scan-File in docscan-watcher.ps1 (a vendor match
 * makes a document at least MEDIUM and a general file HIGH; a ZIP under another name gets MEDIUM for
 * a match inside it), plus the Android rules for packages. And the human-readable summary (Get-Summary).
 */
public final class Verdicts {
    public static final class Merged {
        public String verdict = "INFO";
        public final List<String> yaraFileMatches = new ArrayList<>();
        /** Findings decided on the Android side (APK policy, APK in an archive). */
        public final List<ApkInspector.Finding> androidFindings = new ArrayList<>();
        public boolean apk;
    }

    private Verdicts() {}

    /**
     * @param category    WatchFilter category of the file name
     * @param archiveExt  .zip / .apks / .xapk / .apkm (the $isZip of the PC watcher)
     * @param apkReport   the APK policy result (null when the file is not a package)
     */
    public static Merged merge(String category, boolean archiveExt, ScanResult r, ApkInspector.Report apkReport) {
        Merged m = new Merged();
        if (r.json == null) {          // the scan itself failed (worker crash, unreadable file)
            m.verdict = "ERROR";
            if (apkReport != null) {
                m.androidFindings.addAll(apkReport.findings);
                m.verdict = ApkInspector.rank(apkReport.verdict) > 0 ? apkReport.verdict : "ERROR";
            }
            return m;
        }
        JSONObject o = r.json;
        boolean doc = WatchFilter.DOCUMENT.equals(category);
        m.apk = WatchFilter.APK.equals(category) || r.isApk;
        Set<String> matches = new LinkedHashSet<>(strings(o.optJSONArray("yara_file_matches")));
        List<String> partRules = partRules(o.optJSONArray("yara_part_matches"));

        String v;
        if (m.apk) {
            // A package is a ZIP for the docscan module: its archive rules (a .js asset = "ARCHIVE_SCRIPT")
            // say nothing about an app - only the other policy findings count.
            v = policyVerdictWithout(o, "ARCHIVE_", "ZIP_");
            if (!matches.isEmpty()) v = "HIGH";                       // a vendor rule on the package itself
            List<String> dexRules = r.dex != null ? partRules(r.dex.optJSONArray("dex")) : new ArrayList<>();
            if (!dexRules.isEmpty()) v = "HIGH";                      // a vendor rule on the app code
            matches.addAll(dexRules);
            // Files inside the package (game data, bundled archives): mostly document rules that fire on
            // binary assets - recorded, but they do not raise the verdict (the PC watcher, too, counts
            // document rules only for documents).
            matches.addAll(partRules);
            if (apkReport != null) {
                m.androidFindings.addAll(apkReport.findings);
                v = ApkInspector.max(v, apkReport.verdict);
            }
        } else {
            v = r.verdict == ScanResult.Verdict.ERROR ? "INFO" : r.verdict.name();
            if (doc || archiveExt) {
                matches.addAll(strings(o.optJSONArray("yara_doc_matches")));
                matches.addAll(partRules);
                matches.addAll(strings(o.optJSONArray("yara_matches")));
            }
            if (!matches.isEmpty()) v = doc ? ApkInspector.max(v, "MEDIUM") : "HIGH";
            // an archive under another name: a vendor rule on a file inside it -> MEDIUM
            if ("zip".equals(r.fileType) && !doc && !archiveExt && !partRules.isEmpty()) {
                matches.addAll(partRules);
                v = ApkInspector.max(v, "MEDIUM");
            }
            // Android: a package inside an archive (.xapk / .apks bundles, or an APK sent in a zip)
            for (String e : r.archiveEntries) {
                if (e.toLowerCase(Locale.ROOT).endsWith(".apk")) {
                    m.androidFindings.add(new ApkInspector.Finding("APK_IN_ARCHIVE", "MEDIUM",
                            "Архів містить застосунок Android (" + e + ") — перевірте джерело перед встановленням"));
                    v = ApkInspector.max(v, "MEDIUM");
                    break;
                }
            }
        }
        m.verdict = v;
        m.yaraFileMatches.addAll(matches);
        return m;
    }

    /** Highest severity of the matching policy rules ("details") whose finding has none of the prefixes. */
    static String policyVerdictWithout(JSONObject o, String... prefixes) {
        JSONArray details = o.optJSONArray("details");
        String v = "INFO";
        for (int i = 0; details != null && i < details.length(); i++) {
            JSONObject d = details.optJSONObject(i);
            if (d == null) continue;
            String f = d.optString("finding");
            boolean skip = false;
            for (String p : prefixes) if (f.startsWith(p)) skip = true;
            if (!skip) v = ApkInspector.max(v, d.optString("severity"));
        }
        return v;
    }

    /**
     * Get-Summary of docscan-watcher.ps1: what was found (policy texts, vendor rules with where and
     * their description) and what was done; at most 600 characters.
     */
    public static String summary(ScanResult r, Merged m, String disarm, List<String> errors) {
        List<String> p = new ArrayList<>();
        JSONObject o = r.json;
        if (o != null && !m.apk) p.addAll(strings(o.optJSONArray("findings_text")));
        for (ApkInspector.Finding f : m.androidFindings) p.add(f.text);

        Map<String, String> where = new HashMap<>();
        Map<String, String> desc = new HashMap<>();
        if (o != null) {
            JSONArray pm = o.optJSONArray("yara_part_matches");
            for (int i = 0; pm != null && i < pm.length(); i++) {
                JSONObject x = pm.optJSONObject(i);
                if (x == null) continue;
                for (String rule : strings(x.optJSONArray("rules"))) {
                    if (!where.containsKey(rule)) where.put(rule, x.optString("part"));
                }
            }
            for (String rule : strings(o.optJSONArray("yara_matches"))) {
                if (!where.containsKey(rule)) where.put(rule, "macro code");
            }
            descriptions(o.optJSONArray("yara_descriptions"), desc);
        }
        if (r.dex != null) {
            JSONArray dx = r.dex.optJSONArray("dex");
            for (int i = 0; dx != null && i < dx.length(); i++) {
                JSONObject x = dx.optJSONObject(i);
                if (x == null) continue;
                for (String rule : strings(x.optJSONArray("rules"))) {
                    if (!where.containsKey(rule)) where.put(rule, x.optString("part"));
                }
            }
            descriptions(r.dex.optJSONArray("descriptions"), desc);
        }
        for (String rule : m.yaraFileMatches) {
            String t = "YARA " + rule;
            if (where.containsKey(rule)) t += " (in " + where.get(rule) + ")";
            if (desc.containsKey(rule)) t += " - " + desc.get(rule);
            p.add(t);
        }
        if (disarm != null) p.add("action: " + disarm);
        if (("ERROR".equals(m.verdict) || "SKIPPED".equals(m.verdict)) && errors != null && !errors.isEmpty()) {
            p.add(String.join("; ", errors));
        }
        String t = String.join(" | ", p);
        if (t.length() > 600) t = t.substring(0, 597) + "...";
        return t;
    }

    private static void descriptions(JSONArray a, Map<String, String> out) {
        for (int i = 0; a != null && i < a.length(); i++) {
            JSONObject d = a.optJSONObject(i);
            if (d != null && !out.containsKey(d.optString("rule"))) out.put(d.optString("rule"), d.optString("description"));
        }
    }

    private static List<String> partRules(JSONArray parts) {
        List<String> out = new ArrayList<>();
        for (int i = 0; parts != null && i < parts.length(); i++) {
            JSONObject p = parts.optJSONObject(i);
            if (p == null) continue;
            for (String s : strings(p.optJSONArray("rules"))) if (!out.contains(s)) out.add(s);
        }
        return out;
    }

    static List<String> strings(JSONArray a) {
        List<String> out = new ArrayList<>();
        for (int i = 0; a != null && i < a.length(); i++) {
            String s = a.optString(i, null);
            if (s != null && !s.isEmpty()) out.add(s);
        }
        return out;
    }
}
