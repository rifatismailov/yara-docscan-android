package yara.docscan.android;

import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import yara.docscan.android.ui.JournalTab;
import yara.docscan.android.ui.OverviewTab;
import yara.docscan.android.ui.Permissions;
import yara.docscan.android.ui.QuarantineTab;
import yara.docscan.android.ui.ScanTab;
import yara.docscan.android.watch.Notifier;
import yara.docscan.android.watch.WatchSettings;
import yara.docscan.android.watch.WatcherService;

public class MainActivity extends AppCompatActivity {
    public static final String EXTRA_TAB = "tab";
    public static final String TAB_OVERVIEW = "overview";
    public static final String TAB_JOURNAL = "journal";
    public static final String TAB_QUARANTINE = "quarantine";
    public static final String TAB_SCAN = "scan";
    private static final long REFRESH_MS = 2000;

    private final ExecutorService bg = Executors.newSingleThreadExecutor();
    private final ExecutorService scanBg = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private View vOverview, vJournal, vQuarantine, vScan;
    private BottomNavigationView nav;
    private OverviewTab overview;
    private JournalTab journal;
    private QuarantineTab quarantine;
    private ScanTab scan;
    private String current = TAB_OVERVIEW;

    private final ActivityResultLauncher<String[]> picker =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
                if (uri != null) scan.scan(uri);
            });

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            if (TAB_OVERVIEW.equals(current)) overview.refresh();
            else if (TAB_JOURNAL.equals(current)) journal.refresh();
            ui.postDelayed(this, REFRESH_MS);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Notifier.createChannels(this);
        vOverview = findViewById(R.id.view_overview);
        vJournal = findViewById(R.id.view_journal);
        vQuarantine = findViewById(R.id.view_quarantine);
        vScan = findViewById(R.id.view_scan);

        overview = new OverviewTab(this, vOverview, bg);
        journal = new JournalTab(this, vJournal, bg);
        quarantine = new QuarantineTab(this, vQuarantine, bg);
        scan = new ScanTab(this, vScan, scanBg, () -> picker.launch(new String[] {"*/*"}));

        nav = findViewById(R.id.nav);
        nav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            show(id == R.id.tab_journal ? TAB_JOURNAL : id == R.id.tab_quarantine ? TAB_QUARANTINE
                    : id == R.id.tab_scan ? TAB_SCAN : TAB_OVERVIEW);
            return true;
        });

        // protection was on, but the service is not running (killed, app updated): bring it back
        if (new WatchSettings(this).enabled() && !WatcherService.running && Permissions.storage(this)) {
            WatcherService.start(this);
        }
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(ticker);
        if (TAB_QUARANTINE.equals(current)) quarantine.refresh();
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(ticker);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        bg.shutdownNow();
        scanBg.shutdownNow();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        overview.refresh();
    }

    private void show(String tab) {
        current = tab;
        vOverview.setVisibility(TAB_OVERVIEW.equals(tab) ? View.VISIBLE : View.GONE);
        vJournal.setVisibility(TAB_JOURNAL.equals(tab) ? View.VISIBLE : View.GONE);
        vQuarantine.setVisibility(TAB_QUARANTINE.equals(tab) ? View.VISIBLE : View.GONE);
        vScan.setVisibility(TAB_SCAN.equals(tab) ? View.VISIBLE : View.GONE);
        switch (tab) {
            case TAB_OVERVIEW: overview.refresh(); overview.refreshDevice(); break;
            case TAB_JOURNAL: journal.refresh(); break;
            case TAB_QUARANTINE: quarantine.refresh(); break;
            default: break;
        }
    }

    private void select(String tab) {
        int id = TAB_JOURNAL.equals(tab) ? R.id.tab_journal : TAB_QUARANTINE.equals(tab) ? R.id.tab_quarantine
                : TAB_SCAN.equals(tab) ? R.id.tab_scan : R.id.tab_overview;
        nav.setSelectedItemId(id);
        show(tab);
    }

    @SuppressWarnings("deprecation")
    private void handleIntent(Intent intent) {
        if (intent == null) return;
        Uri uri = null;
        if (Intent.ACTION_VIEW.equals(intent.getAction())) uri = intent.getData();
        else if (Intent.ACTION_SEND.equals(intent.getAction())) {
            uri = Build.VERSION.SDK_INT >= 33 ? intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class)
                    : intent.getParcelableExtra(Intent.EXTRA_STREAM);
        }
        if (uri != null) {
            select(TAB_SCAN);
            scan.scan(uri);
            return;
        }
        String tab = intent.getStringExtra(EXTRA_TAB);
        select(tab != null ? tab : current);
    }
}
