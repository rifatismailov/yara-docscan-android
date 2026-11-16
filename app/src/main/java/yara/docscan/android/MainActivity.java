package yara.docscan.android;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.ScanResult;

public class MainActivity extends AppCompatActivity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private Button pick;
    private ProgressBar progress;
    private TextView status, file, verdict, findings, json;
    private volatile DocScanner scanner;
    private Uri pending;   // a document shared to us before the rules were ready

    private final ActivityResultLauncher<String[]> picker =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
                if (uri != null) scan(uri);
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        pick = findViewById(R.id.pick);
        progress = findViewById(R.id.progress);
        status = findViewById(R.id.status);
        file = findViewById(R.id.file);
        verdict = findViewById(R.id.verdict);
        findings = findViewById(R.id.findings);
        json = findViewById(R.id.json);

        pick.setOnClickListener(v -> picker.launch(new String[] {"*/*"}));
        pending = incomingUri(getIntent());
        loadRules();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Uri uri = incomingUri(intent);
        if (uri != null) scan(uri);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        worker.shutdownNow();
    }

    private void loadRules() {
        status.setText(R.string.loading_rules);
        progress.setVisibility(View.VISIBLE);
        worker.execute(() -> {
            try {
                long t0 = System.currentTimeMillis();
                DocScanner s = DocScanner.get(this);
                long ms = System.currentTimeMillis() - t0;
                ui.post(() -> {
                    scanner = s;
                    progress.setVisibility(View.GONE);
                    pick.setEnabled(true);
                    status.setText(getString(R.string.rules_ready, DocScanner.yaraVersion(), ms));
                    if (pending != null) {
                        scan(pending);
                        pending = null;
                    }
                });
            } catch (Exception e) {
                ui.post(() -> {
                    progress.setVisibility(View.GONE);
                    status.setText(getString(R.string.rules_failed, e.getMessage()));
                });
            }
        });
    }

    private void scan(Uri uri) {
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
        worker.execute(() -> {
            long t0 = System.currentTimeMillis();
            ScanResult r = null;
            String err = null;
            try {
                r = scanner.scan(this, uri);
            } catch (Exception e) {
                err = e.getMessage();
            }
            long ms = System.currentTimeMillis() - t0;
            ScanResult res = r;
            String error = err;
            ui.post(() -> {
                progress.setVisibility(View.GONE);
                pick.setEnabled(true);
                if (res == null) {
                    status.setText(getString(R.string.scan_failed, error));
                } else {
                    show(res, ms);
                }
            });
        });
    }

    private void show(ScanResult r, long ms) {
        status.setText(getString(R.string.scan_time, ms));
        file.setText(r.fileName + "  ·  " + r.fileType);

        verdict.setVisibility(View.VISIBLE);
        verdict.setText(r.verdict.name());
        int color;
        switch (r.verdict) {
            case HIGH: color = Color.rgb(0xC6, 0x28, 0x28); break;
            case MEDIUM: color = Color.rgb(0xEF, 0x6C, 0x00); break;
            case INFO: color = Color.rgb(0x2E, 0x7D, 0x32); break;
            default: color = Color.GRAY;
        }
        verdict.setBackgroundColor(color);

        StringBuilder sb = new StringBuilder();
        if (r.error != null) sb.append(r.error).append('\n');
        for (String t : r.findingsText) sb.append("• ").append(t).append('\n');
        if (r.findingsText.isEmpty() && !r.findings.isEmpty()) {
            for (String f : r.findings) sb.append("• ").append(f).append('\n');
        }
        if (!r.vendorMatches.isEmpty()) {
            sb.append('\n').append(getString(R.string.vendor_rules)).append('\n');
            for (String m : r.vendorMatches) sb.append("  ").append(m).append('\n');
        }
        if (r.disarmNeeded) sb.append('\n').append(getString(R.string.disarm_possible));
        if (r.timeout) sb.append('\n').append(getString(R.string.scan_timeout));
        if (sb.length() == 0) sb.append(getString(R.string.nothing_found));
        findings.setText(sb.toString().trim());

        try {
            json.setText(new JSONObject(r.rawJson).toString(2));
        } catch (Exception e) {
            json.setText(r.rawJson);
        }
    }

    @SuppressWarnings("deprecation")
    private static Uri incomingUri(Intent intent) {
        if (intent == null) return null;
        if (Intent.ACTION_VIEW.equals(intent.getAction())) return intent.getData();
        if (Intent.ACTION_SEND.equals(intent.getAction())) {
            if (Build.VERSION.SDK_INT >= 33) return intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
            return intent.getParcelableExtra(Intent.EXTRA_STREAM);
        }
        return null;
    }
}
