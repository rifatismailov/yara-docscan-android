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

    /** docscan_disarm_plan() results (libyara/include/yara/docscan_disarm.h). */
    public static final int DISARM_NOT_PLANNED = -1;
    public static final int DISARM_NONE = 0;
    public static final int DISARM_DELETE = 1;
    public static final int DISARM_REPLACE = 2;
    public static final int DISARM_FAILED = 3;

    public final String fileName;
    public final String fileType;
    /** The policy verdict of the docscan module (watcher-level merging is in watch.Verdicts). */
    public final Verdict verdict;
    public final List<String> findings;
    public final List<String> findingsText;
    /** All vendor matches: file + document + VBA + parts + dex, de-duplicated. */
    public final List<String> vendorMatches;
    public final List<String> archiveEntries;
    /** A ZIP with AndroidManifest.xml + classes.dex at its root. */
    public final boolean isApk;
    public final boolean disarmNeeded;
    public final int disarmKind;
    public final String disarmAction;
    public final boolean timeout;
    public final String error;
    /** The docscan JSON object (null for errors before the scan). */
    public final JSONObject json;
    /** Vendor matches in classes*.dex: {"dex":[{"part":..,"rules":[..]}],...} or null. */
    public final JSONObject dex;

    private ScanResult(String fileName, String fileType, Verdict verdict, List<String> findings,
                       List<String> findingsText, List<String> vendorMatches, List<String> archiveEntries,
                       boolean isApk, boolean disarmNeeded, int disarmKind, String disarmAction,
                       boolean timeout, String error, JSONObject json, JSONObject dex) {
        this.fileName = fileName;
        this.fileType = fileType;
        this.verdict = verdict;
        this.findings = Collections.unmodifiableList(findings);
        this.findingsText = Collections.unmodifiableList(findingsText);
        this.vendorMatches = Collections.unmodifiableList(vendorMatches);
        this.archiveEntries = Collections.unmodifiableList(archiveEntries);
        this.isApk = isApk;
        this.disarmNeeded = disarmNeeded;
        this.disarmKind = disarmKind;
        this.disarmAction = disarmAction;
        this.timeout = timeout;
        this.error = error;
        this.json = json;
        this.dex = dex;
    }

    static ScanResult error(String fileName, String message) {
        return new ScanResult(fileName, "unknown", Verdict.ERROR, new ArrayList<>(), new ArrayList<>(),
                new ArrayList<>(), new ArrayList<>(), false, false, DISARM_NOT_PLANNED, null, false,
                message, null, null);
    }

    static ScanResult parse(String fileName, String json, String dexJson) {
        JSONObject o;
        try {
            o = new JSONObject(json);
        } catch (JSONException e) {
            return error(fileName, "bad scan output: " + e.getMessage());
        }
        if (o.has("error")) return error(fileName, o.optString("error"));

        JSONObject dex = null;
        if (dexJson != null) {
            try {
                dex = new JSONObject(dexJson);
            } catch (JSONException ignored) {
                // dex scan output is optional
            }
        }

        List<String> vendor = new ArrayList<>();
        addAll(vendor, o.optJSONArray("yara_file_matches"));
        addAll(vendor, o.optJSONArray("yara_doc_matches"));
        addAll(vendor, o.optJSONArray("yara_matches"));
        addParts(vendor, o.optJSONArray("yara_part_matches"));
        if (dex != null) addParts(vendor, dex.optJSONArray("dex"));

        List<String> entries = list(o.optJSONArray("archive_entries"));
        boolean apk = "zip".equals(o.optString("ftype"))
                && entries.contains("AndroidManifest.xml") && entries.contains("classes.dex");

        JSONObject plan = o.optJSONObject("disarm_plan");
        JSONObject res = o.optJSONObject("disarm_result");
        Verdict v;
        try {
            v = Verdict.valueOf(o.optString("verdict", "INFO"));
        } catch (IllegalArgumentException e) {
            v = Verdict.INFO;
        }
        return new ScanResult(
                fileName,
                o.optString("ftype", "unknown"),
                v,
                list(o.optJSONArray("findings")),
                list(o.optJSONArray("findings_text")),
                vendor,
                entries,
                apk,
                plan != null && plan.optBoolean("needed"),
                res != null ? res.optInt("kind", DISARM_NOT_PLANNED) : DISARM_NOT_PLANNED,
                res != null ? res.optString("action", "") : null,
                o.optBoolean("timeout"),
                null,
                o,
                dex);
    }

    /** The JSON as text (for display / the results log). */
    public String rawJson() {
        return json != null ? json.toString() : "{\"error\":" + JSONObject.quote(error) + "}";
    }

    private static void addParts(List<String> out, JSONArray parts) {
        if (parts == null) return;
        for (int i = 0; i < parts.length(); i++) {
            JSONObject p = parts.optJSONObject(i);
            if (p != null) addAll(out, p.optJSONArray("rules"));
        }
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
