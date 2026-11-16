package yara.docscan.android.scan;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** One parsed docscan JSON object (the same fields as {@code yara64 --docscan-json}). */
public final class ScanResult {
    public enum Verdict { INFO, MEDIUM, HIGH, ERROR }

    public final String fileName;
    public final String fileType;
    public final Verdict verdict;
    public final List<String> findings;
    public final List<String> findingsText;
    public final List<String> vendorMatches;   // file + document + VBA + parts, de-duplicated
    public final boolean disarmNeeded;
    public final boolean timeout;
    public final String error;
    public final String rawJson;

    private ScanResult(String fileName, String fileType, Verdict verdict, List<String> findings,
                       List<String> findingsText, List<String> vendorMatches, boolean disarmNeeded,
                       boolean timeout, String error, String rawJson) {
        this.fileName = fileName;
        this.fileType = fileType;
        this.verdict = verdict;
        this.findings = Collections.unmodifiableList(findings);
        this.findingsText = Collections.unmodifiableList(findingsText);
        this.vendorMatches = Collections.unmodifiableList(vendorMatches);
        this.disarmNeeded = disarmNeeded;
        this.timeout = timeout;
        this.error = error;
        this.rawJson = rawJson;
    }

    static ScanResult parse(String fileName, String json) throws JSONException {
        JSONObject o = new JSONObject(json);
        if (o.has("error")) {
            return new ScanResult(fileName, "unknown", Verdict.ERROR, new ArrayList<>(),
                    new ArrayList<>(), new ArrayList<>(), false, false, o.optString("error"), json);
        }
        List<String> vendor = new ArrayList<>();
        addAll(vendor, o.optJSONArray("yara_file_matches"));
        addAll(vendor, o.optJSONArray("yara_doc_matches"));
        addAll(vendor, o.optJSONArray("yara_matches"));
        JSONArray parts = o.optJSONArray("yara_part_matches");
        if (parts != null) {
            for (int i = 0; i < parts.length(); i++) {
                JSONObject p = parts.optJSONObject(i);
                if (p != null) addAll(vendor, p.optJSONArray("rules"));
            }
        }
        JSONObject plan = o.optJSONObject("disarm_plan");
        return new ScanResult(
                fileName,
                o.optString("ftype", "unknown"),
                Verdict.valueOf(o.optString("verdict", "INFO")),
                list(o.optJSONArray("findings")),
                list(o.optJSONArray("findings_text")),
                vendor,
                plan != null && plan.optBoolean("needed"),
                o.optBoolean("timeout"),
                null,
                json);
    }

    private static List<String> list(JSONArray a) {
        List<String> out = new ArrayList<>();
        addAll(out, a);
        return out;
    }

    private static void addAll(List<String> out, JSONArray a) {
        if (a == null) return;
        for (int i = 0; i < a.length(); i++) {
            String s = a.optString(i, null);
            if (s != null && !out.contains(s)) out.add(s);
        }
    }
}
