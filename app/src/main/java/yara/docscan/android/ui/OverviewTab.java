package yara.docscan.android.ui;

import android.app.Activity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.TextView;

import java.util.List;
import java.util.concurrent.ExecutorService;

import yara.docscan.android.R;
import yara.docscan.android.device.DevicePosture;
import yara.docscan.android.watch.FileIndex;
import yara.docscan.android.watch.ResultLog;
import yara.docscan.android.watch.WatchSettings;
import yara.docscan.android.watch.WatcherService;

/** "Захист": the watcher on / off, permissions, settings, device security. */
public final class OverviewTab {
    private final Activity a;
    private final ExecutorService bg;
    private final WatchSettings settings;
    private final TextView title, text, stats;
    private final Button toggle;
    private final ViewGroup permissions, deviceChecks;
    private final CompoundButton cure, quarantineApk;

    public OverviewTab(Activity a, View root, ExecutorService bg) {
        this.a = a;
        this.bg = bg;
        this.settings = new WatchSettings(a);
        title = root.findViewById(R.id.status_title);
        text = root.findViewById(R.id.status_text);
        stats = root.findViewById(R.id.stats);
        toggle = root.findViewById(R.id.toggle);
        permissions = root.findViewById(R.id.permissions);
        deviceChecks = root.findViewById(R.id.device_checks);
        cure = root.findViewById(R.id.setting_cure);
        quarantineApk = root.findViewById(R.id.setting_quarantine_apk);
        ((TextView) root.findViewById(R.id.results_file))
                .setText(a.getString(R.string.results_file, ResultLog.get(a).file().getPath()));

        toggle.setOnClickListener(v -> {
            if (settings.enabled()) WatcherService.stop(a);
            else if (Permissions.storage(a)) WatcherService.start(a);
            else Permissions.requestStorage(a);
            v.postDelayed(this::refresh, 300);
        });
        cure.setChecked(settings.cure());
        cure.setOnCheckedChangeListener((b, on) -> {
            settings.setCure(on);
            quarantineApk.setEnabled(on);
        });
        quarantineApk.setChecked(settings.quarantineApk());
        quarantineApk.setEnabled(settings.cure());
        quarantineApk.setOnCheckedChangeListener((b, on) -> settings.setQuarantineApk(on));
        root.findViewById(R.id.device_recheck).setOnClickListener(v -> refreshDevice());
        refreshDevice();
    }

    /** Cheap: called every couple of seconds while the tab is visible. */
    public void refresh() {
        boolean on = settings.enabled();
        boolean storage = Permissions.storage(a);
        title.setText(on && WatcherService.running ? R.string.protection_on : R.string.protection_off);
        title.setTextColor(Ui.verdictColor(a, on && WatcherService.running ? "ok" : "bad"));
        String t = on ? WatcherService.status : (storage ? "" : a.getString(R.string.protection_needs_storage));
        if (on && WatcherService.watchLimitReached) t += "\n" + a.getString(R.string.watch_limit);
        text.setText(t);
        toggle.setText(on ? R.string.protection_stop : R.string.protection_start);
        bg.execute(() -> {
            FileIndex idx = FileIndex.get(a);
            String s = a.getString(R.string.stats, idx.count("files"), idx.count("apps"), idx.countThreats());
            a.runOnUiThread(() -> stats.setText(s));
        });
        refreshPermissions();
    }

    private void refreshPermissions() {
        permissions.removeAllViews();
        perm(Permissions.storage(a), a.getString(R.string.perm_storage), a.getString(R.string.perm_storage_why),
                a.getString(R.string.perm_grant), v -> Permissions.requestStorage(a));
        perm(Permissions.notifications(a), a.getString(R.string.perm_notifications),
                a.getString(R.string.perm_notifications_why), a.getString(R.string.perm_grant),
                v -> Permissions.requestNotifications(a));
        perm(Permissions.battery(a), a.getString(R.string.perm_battery), a.getString(R.string.perm_battery_why),
                a.getString(R.string.perm_grant), v -> Permissions.requestBattery(a));
        String vendor = Permissions.aggressiveVendor();
        if (vendor != null) {
            // cannot be checked: always shown as a reminder
            Ui.row(permissions, "warn", a.getString(R.string.perm_autostart, vendor),
                    a.getString(R.string.perm_autostart_why), a.getString(R.string.perm_open),
                    v -> Permissions.openAutostart(a));
        }
    }

    private void perm(boolean ok, String title, String why, String button, View.OnClickListener l) {
        Ui.row(permissions, ok ? "ok" : "bad", title, ok ? a.getString(R.string.perm_granted) : why,
                ok ? null : button, l);
    }

    public void refreshDevice() {
        bg.execute(() -> {
            List<DevicePosture.Check> checks = DevicePosture.run(a);
            a.runOnUiThread(() -> {
                deviceChecks.removeAllViews();
                for (DevicePosture.Check c : checks) Ui.row(deviceChecks, c.status, c.title, c.detail, null, null);
            });
        });
    }
}
