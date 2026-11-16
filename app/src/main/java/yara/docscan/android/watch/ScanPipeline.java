package yara.docscan.android.watch;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import yara.docscan.android.apk.ApkFacts;
import yara.docscan.android.apk.ApkFactsReader;
import yara.docscan.android.apk.ApkInspector;
import yara.docscan.android.scan.Disarm;
import yara.docscan.android.scan.DocScanException;
import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.Quarantine;
import yara.docscan.android.scan.ScanResult;

/**
 * Scan-File of docscan-watcher.ps1 for one file (and the same for an installed app): wait until the
 * file is written, scan it in the sandbox, cure / quarantine per the settings, write the record
 * (docscan-results.json + journal), alert.
 */
public final class ScanPipeline {
    private static final String TAG = "ScanPipeline";
    private static final long READY_TIMEOUT_MS = 60_000;   // -ReadyTimeout

    public interface Listener {
        /** A file or app was processed (called on the scan thread). */
        void onScanned(String subject, String verdict);
    }

    private final Context ctx;
    private final WatchSettings settings;
    private final FileIndex index;
    private final ResultLog log;
    private final Quarantine quarantine;
    private final String host;
    private final AtomicInteger seq = new AtomicInteger();
    private volatile Listener listener;
    /** Paths the pipeline itself just rewrote (a cured document): their next event is ours. */
    private volatile Suppressor suppressor;

    public interface Suppressor {
        void suppress(String path);
    }

    public ScanPipeline(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        this.settings = new WatchSettings(ctx);
        this.index = FileIndex.get(ctx);
        this.log = ResultLog.get(ctx);
        this.quarantine = new Quarantine(ctx);
        this.host = hostName(ctx);
    }

    public void setListener(Listener l) {
        listener = l;
    }

    public void setSuppressor(Suppressor s) {
        suppressor = s;
    }

    /**
     * @param event Created / Changed / Renamed / Rescan
     * @param force scan even when the index says the file has not changed
     */
    public void scanFile(File f, String event, boolean force) {
        String cat = WatchFilter.category(f.getName());
        if (cat == null) return;
        if (!f.isFile()) {
            index.forgetFile(f.getPath());
            return;
        }
        if (!force && index.isUnchanged(f.getPath(), f.length(), f.lastModified())) return;
        // a file untouched for a while is complete; a fresh one may still be being written
        String state = System.currentTimeMillis() - f.lastModified() > 10_000 ? "ready" : waitReady(f);
        if ("gone".equals(state)) {
            index.forgetFile(f.getPath());
            return;
        }
        long size = f.length(), mtime = f.lastModified();

        List<String> errors = new ArrayList<>();
        if ("timeout".equals(state)) errors.add("file still being written after " + READY_TIMEOUT_MS / 1000 + "s");
        JSONObject rec = baseRecord(event, cat);
        JSONObject docfile = new JSONObject();
        put(docfile, "path", f.getPath());
        put(docfile, "name", f.getName());
        put(docfile, "ext", WatchFilter.ext(f.getName()));
        put(docfile, "size", size);
        put(rec, "docfile", docfile);

        String verdict;
        String summary;
        String disarm = null;
        String sha = null;
        if (size > settings.maxSizeMb() * 1024L * 1024L) {
            verdict = "SKIPPED";
            errors.add("size > " + settings.maxSizeMb() + "MB");
            summary = String.join("; ", errors);
        } else {
            sha = sha256(f);
            if (sha != null) put(docfile, "sha256", sha);
            boolean archiveExt = WatchFilter.isArchiveExt(f.getName());
            boolean doc = WatchFilter.DOCUMENT.equals(cat);
            boolean planCure = settings.cure() && (doc || archiveExt);
            File cured = planCure ? new File(ctx.getCacheDir(), "cured-" + seq.incrementAndGet() + ".tmp") : null;

            ScanResult r;
            try {
                r = DocScanner.get(ctx).scan(f, planCure, cured);
            } catch (DocScanException e) {
                r = ScanResult.error(f.getName(), e.getMessage());
            }
            if (r.error != null) errors.add(r.error);

            ApkInspector.Report apk = null;
            ApkFacts facts = null;
            if (WatchFilter.APK.equals(cat) || r.isApk) {
                facts = ApkFactsReader.fromFile(ctx, f.getPath());
                apk = ApkInspector.inspect(facts);
            }
            Verdicts.Merged m = Verdicts.merge(cat, archiveExt, r, apk);
            verdict = m.verdict;
            String pre = Verdicts.summary(r, m, null, errors);

            if (planCure && !m.apk && r.disarmKind != ScanResult.DISARM_NOT_PLANNED) {
                Suppressor s = suppressor;
                if (s != null) s.suppress(f.getPath());
                disarm = Disarm.apply(f, r, cured, quarantine, pre);
            } else if (m.apk && "HIGH".equals(verdict) && settings.cure() && settings.quarantineApk()) {
                disarm = Disarm.quarantine(f, quarantine, verdict, pre);
            }
            if (cured != null) cured.delete();

            summary = Verdicts.summary(r, m, disarm, errors);
            if (r.json != null) put(rec, "docscan", r.json);
            if (r.dex != null) put(rec, "dex", r.dex);
            put(rec, "yara_file_matches", new JSONArray(m.yaraFileMatches));
            if (!m.androidFindings.isEmpty()) put(rec, "android_findings", findings(m.androidFindings));
            if (facts != null) put(rec, "apk", apkJson(facts));
            if (disarm != null) put(rec, "disarm", disarm);
        }
        put(rec, "verdict", verdict);
        put(rec, "summary", summary);
        if (!errors.isEmpty()) put(rec, "errors", new JSONArray(errors));

        // index: the state after the cure (a deleted file is forgotten)
        if (f.exists()) index.putFile(f.getPath(), f.length(), f.lastModified(), sha, verdict);
        else index.forgetFile(f.getPath());
        finish("file", f.getPath(), f.getName(), verdict, summary, rec, null, null);
    }

    /** An installed (non-system) app: its base.apk through the same scan + the APK policy. */
    public void scanApp(String pkg, String event) {
        PackageManager pm = ctx.getPackageManager();
        PackageInfo pi;
        ApkFacts facts;
        try {
            pi = pm.getPackageInfo(pkg, 0);
            facts = ApkFactsReader.fromInstalled(ctx, pkg);
        } catch (PackageManager.NameNotFoundException e) {
            return;   // uninstalled meanwhile
        }
        ApplicationInfo ai = pi.applicationInfo;
        if (ai == null || facts.systemApp || pkg.equals(ctx.getPackageName())) return;

        List<String> errors = new ArrayList<>();
        ScanResult r;
        try {
            r = DocScanner.get(ctx).scan(new File(ai.sourceDir));
        } catch (DocScanException e) {
            r = ScanResult.error(pkg, e.getMessage());
        }
        if (r.error != null) errors.add(r.error);
        ApkInspector.Report apk = ApkInspector.inspect(facts);
        Verdicts.Merged m = Verdicts.merge(WatchFilter.APK, false, r, apk);
        String summary = Verdicts.summary(r, m, null, errors);

        JSONObject rec = baseRecord(event, "app");
        JSONObject app = apkJson(facts);
        put(app, "path", ai.sourceDir);
        put(rec, "app", app);
        put(rec, "verdict", m.verdict);
        if (r.json != null) put(rec, "docscan", r.json);
        if (r.dex != null) put(rec, "dex", r.dex);
        put(rec, "yara_file_matches", new JSONArray(m.yaraFileMatches));
        put(rec, "android_findings", findings(m.androidFindings));
        put(rec, "summary", summary);
        if (!errors.isEmpty()) put(rec, "errors", new JSONArray(errors));

        index.putApp(pkg, pi.lastUpdateTime, m.verdict);
        finish("app", pkg, facts.label.isEmpty() ? pkg : facts.label, m.verdict, summary, rec, pkg, facts.label);
    }

    /** Apps installed or updated since they were last scanned (the catch-up after a restart). */
    public List<String> changedApps() {
        List<String> out = new ArrayList<>();
        for (PackageInfo pi : ctx.getPackageManager().getInstalledPackages(0)) {
            ApplicationInfo ai = pi.applicationInfo;
            if (ai == null || (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0) continue;
            if (pi.packageName.equals(ctx.getPackageName())) continue;
            if (index.appUpdateTime(pi.packageName) != pi.lastUpdateTime) out.add(pi.packageName);
        }
        return out;
    }

    private void finish(String kind, String subject, String name, String verdict, String summary,
                        JSONObject rec, String pkg, String label) {
        boolean written = log.append(subject, rec);
        index.addEvent(kind, subject, verdict, summary, rec.toString());
        // the catch-up sweep (event "Rescan") alerts only for HIGH: preinstalled / long-present MEDIUM
        // items are in the journal; new files and new installs alert for MEDIUM too
        String event = rec.optString("event");
        boolean alert = written && ("HIGH".equals(verdict) || ("MEDIUM".equals(verdict) && !"Rescan".equals(event)));
        if (alert) {
            if (pkg != null) Notifier.appThreat(ctx, verdict, pkg, label == null || label.isEmpty() ? pkg : label, summary);
            else Notifier.fileThreat(ctx, verdict, name, summary);
        }
        Log.i(TAG, String.format(Locale.ROOT, "%-7s %-8s %s  %s", verdict, kind, subject, summary));
        Listener l = listener;
        if (l != null) l.onScanned(subject, verdict);
    }

    private JSONObject baseRecord(String event, String category) {
        JSONObject rec = new JSONObject();
        put(rec, "timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.ROOT).format(new Date()));
        put(rec, "source", "docscan");
        put(rec, "platform", "android");
        put(rec, "host", host);
        put(rec, "event", event);
        put(rec, "category", category);
        return rec;
    }

    private static JSONArray findings(List<ApkInspector.Finding> list) {
        JSONArray a = new JSONArray();
        for (ApkInspector.Finding f : list) {
            JSONObject o = new JSONObject();
            put(o, "finding", f.finding);
            put(o, "severity", f.severity);
            put(o, "text", f.text);
            a.put(o);
        }
        return a;
    }

    private static JSONObject apkJson(ApkFacts f) {
        JSONObject o = new JSONObject();
        put(o, "package", f.packageName);
        put(o, "label", f.label);
        put(o, "version", f.versionName);
        put(o, "target_sdk", f.targetSdk);
        put(o, "parsed", f.parsed);
        if (f.installed) {
            put(o, "installer", f.installer == null ? "" : f.installer);
        }
        put(o, "signers", new JSONArray(f.signers));
        return o;
    }

    /** Wait-FileReady: the file can be read and its size stays the same for 0.5 s. */
    private static String waitReady(File f) {
        long deadline = SystemClock.elapsedRealtime() + READY_TIMEOUT_MS;
        long last = -1;
        while (SystemClock.elapsedRealtime() < deadline) {
            if (!f.isFile()) return "gone";
            long len = f.length();
            if (len == last && f.canRead()) return "ready";
            last = len;
            SystemClock.sleep(500);
        }
        return "timeout";
    }

    static String sha256(File f) {
        try (InputStream in = new FileInputStream(f)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[256 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (IOException | java.security.NoSuchAlgorithmException e) {
            return null;
        }
    }

    static String hostName(Context ctx) {
        String n = null;
        if (Build.VERSION.SDK_INT >= 25) {
            try {
                n = Settings.Global.getString(ctx.getContentResolver(), Settings.Global.DEVICE_NAME);
            } catch (RuntimeException ignored) {
                // not available on some ROMs
            }
        }
        return n != null && !n.isEmpty() ? n : Build.MANUFACTURER + " " + Build.MODEL;
    }

    static void put(JSONObject o, String k, Object v) {
        try {
            o.put(k, v);
        } catch (JSONException ignored) {
            // only non-finite numbers throw
        }
    }
}
