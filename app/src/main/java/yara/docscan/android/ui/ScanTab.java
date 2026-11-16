package yara.docscan.android.ui;

import android.app.Activity;
import android.net.Uri;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.util.concurrent.ExecutorService;

import yara.docscan.android.R;
import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.ScanResult;

/** "Перевірити": scan one file picked by the user or shared to DocScan (detection only). */
public final class ScanTab {
    private final Activity a;
    private final ExecutorService bg;
    private final Button pick;
    private final ProgressBar progress;
    private final TextView status, file, verdict, findings, json;
    private volatile DocScanner scanner;
    private Uri pending;

    public ScanTab(Activity a, View root, ExecutorService bg, Runnable onPick) {
        this.a = a;
        this.bg = bg;
        pick = root.findViewById(R.id.pick);
        progress = root.findViewById(R.id.progress);
        status = root.findViewById(R.id.scan_status);
        file = root.findViewById(R.id.file);
        verdict = root.findViewById(R.id.verdict);
        findings = root.findViewById(R.id.findings);
        json = root.findViewById(R.id.json);
        pick.setOnClickListener(v -> onPick.run());
        loadRules();
    }

    private void loadRules() {
        status.setText(R.string.loading_rules);
        progress.setVisibility(View.VISIBLE);
        bg.execute(() -> {
            try {
                long t0 = System.currentTimeMillis();
                DocScanner s = DocScanner.get(a);
                long ms = System.currentTimeMillis() - t0;
                a.runOnUiThread(() -> {
                    scanner = s;
                    progress.setVisibility(View.GONE);
                    pick.setEnabled(true);
                    status.setText(a.getString(R.string.rules_ready, s.yaraVersion(), ms));
                    if (pending != null) {
                        scan(pending);
                        pending = null;
                    }
                });
            } catch (Exception e) {
                a.runOnUiThread(() -> {
                    progress.setVisibility(View.GONE);
                    status.setText(a.getString(R.string.rules_failed, e.getMessage()));
                });
            }
        });
    }

    public void scan(Uri uri) {
        if (scanner == null) {
            pending = uri;
            return;
        }
        progress.setVisibility(View.VISIBLE);
        pick.setEnabled(false);
        verdict.setVisibility(View.GONE);
        findings.setText("");
        json.setText("");
        file.setText(uri.getLastPathSegment());
        bg.execute(() -> {
            long t0 = System.currentTimeMillis();
            ScanResult r;
            try {
                r = scanner.scan(uri);
            } catch (Exception e) {
                r = ScanResult.error(String.valueOf(uri.getLastPathSegment()), e.getMessage());
            }
            long ms = System.currentTimeMillis() - t0;
            ScanResult res = r;
            a.runOnUiThread(() -> {
                progress.setVisibility(View.GONE);
                pick.setEnabled(true);
                show(res, ms);
            });
        });
    }

    private void show(ScanResult r, long ms) {
        status.setText(a.getString(R.string.scan_time, ms));
        file.setText(r.fileName + "  ·  " + r.fileType + (r.isApk ? " (APK)" : ""));
        verdict.setVisibility(View.VISIBLE);
        Ui.badge(verdict, r.verdict.name());

        StringBuilder sb = new StringBuilder();
        if (r.error != null) sb.append(r.error).append('\n');
        if (!r.isApk) {
            for (String t : r.findingsText) sb.append("• ").append(t).append('\n');
            if (r.findingsText.isEmpty()) for (String f : r.findings) sb.append("• ").append(f).append('\n');
        }
        if (!r.vendorMatches.isEmpty()) {
            sb.append('\n').append(a.getString(R.string.vendor_rules)).append('\n');
            for (String m : r.vendorMatches) sb.append("  ").append(m).append('\n');
        }
        if (r.disarmNeeded) sb.append('\n').append(a.getString(R.string.disarm_possible));
        if (r.timeout) sb.append('\n').append(a.getString(R.string.scan_timeout));
        if (sb.length() == 0) sb.append(a.getString(R.string.nothing_found));
        findings.setText(sb.toString().trim());
        try {
            json.setText(r.json != null ? r.json.toString(2) : r.rawJson());
        } catch (Exception e) {
            json.setText(r.rawJson());
        }
    }
}
