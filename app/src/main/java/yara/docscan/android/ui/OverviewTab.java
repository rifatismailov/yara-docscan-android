package yara.docscan.android.ui;

import android.app.Activity;
import android.net.Uri;
import android.text.format.DateUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;

import yara.docscan.android.R;
import yara.docscan.android.device.DevicePosture;
import yara.docscan.android.scan.RulesBundle;
import yara.docscan.android.watch.CriticalQueue;
import yara.docscan.android.watch.FileIndex;
import yara.docscan.android.watch.MacroStore;
import yara.docscan.android.watch.WatchFilter;
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
    private final CompoundButton cure, quarantineApk, quarantineGeneral;
    private final TextView macroStatus, criticalStatus, rulesStatus;
    private final CompoundButton criticalSwitch;

    public OverviewTab(Activity a, View root, ExecutorService bg, Runnable pickRulesBundle) {
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
        quarantineGeneral = root.findViewById(R.id.setting_quarantine_general);
        macroStatus = root.findViewById(R.id.macro_status);
        criticalStatus = root.findViewById(R.id.critical_status);
        rulesStatus = root.findViewById(R.id.rules_status);
        criticalSwitch = root.findViewById(R.id.critical_switch);
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
            quarantineGeneral.setEnabled(on);
        });
        quarantineApk.setChecked(settings.quarantineApk());
        quarantineApk.setEnabled(settings.cure());
        quarantineApk.setOnCheckedChangeListener((b, on) -> settings.setQuarantineApk(on));
        quarantineGeneral.setChecked(settings.quarantineGeneral());
        quarantineGeneral.setEnabled(settings.cure());
        quarantineGeneral.setOnCheckedChangeListener((b, on) -> settings.setQuarantineGeneral(on));

        root.findViewById(R.id.macro_url).setOnClickListener(v ->
                askText(R.string.macro_set_url, R.string.macro_url_hint, settings.macroUploadUrl(), url -> {
                    settings.setMacroUploadUrl(url);
                    refreshStores();
                    if (!url.isEmpty()) bg.execute(() -> new MacroStore(a).sync(url));   // send what is stored
                }));
        root.findViewById(R.id.rules_file).setOnClickListener(v -> pickRulesBundle.run());
        root.findViewById(R.id.rules_url).setOnClickListener(v ->
                askText(R.string.rules_from_url, R.string.rules_url_hint, settings.rulesUrl(), url -> {
                    settings.setRulesUrl(url);
                    if (!url.isEmpty()) installRules(() -> RulesBundle.installFromUrl(a, url, false));
                }));
        root.findViewById(R.id.rules_check).setOnClickListener(v -> {
            String url = settings.rulesUrl();
            if (url.isEmpty()) {
                new AlertDialog.Builder(a).setMessage(R.string.rules_no_url).setPositiveButton(R.string.ok, null).show();
            } else {
                installRules(() -> RulesBundle.installFromUrl(a, url, true));
            }
        });
        criticalSwitch.setChecked(settings.criticalEnabled());
        criticalSwitch.setOnCheckedChangeListener((b, on) -> {
            settings.setCriticalEnabled(on);
            WatchFilter.criticalActive(a);
            refreshStores();
        });
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
        refreshStores();
    }

    private void refreshStores() {
        String url = settings.macroUploadUrl();
        macroStatus.setText(a.getString(R.string.macro_status, new MacroStore(a).count(),
                url.isEmpty() ? a.getString(R.string.macro_local) : a.getString(R.string.macro_upload, url)));
        RulesBundle.Info info = RulesBundle.info(a);
        if (info == null) {
            rulesStatus.setText(R.string.rules_builtin);
        } else {
            List<String> crit = RulesBundle.criticalNames(info);
            rulesStatus.setText(a.getString(R.string.rules_installed, info.manifest.version,
                    DateUtils.getRelativeTimeSpanString(info.installedAt),
                    a.getString(RulesBundle.detectionRules(a) != null ? R.string.rules_detection_bundle : R.string.rules_detection_builtin),
                    crit.isEmpty() ? a.getString(R.string.rules_none) : String.join(", ", crit),
                    info.origin + (info.origin.equals(settings.rulesUrl()) ? "\n" + a.getString(R.string.rules_url_auto) : "")));
        }
        if (!settings.criticalEnabled()) criticalStatus.setText(R.string.critical_status_off);
        else if (RulesBundle.criticalRules(a) == null) criticalStatus.setText(R.string.critical_status_no_rules);
        else criticalStatus.setText(a.getString(R.string.critical_status_on,
                    String.join(", ", RulesBundle.criticalNames(info)), CriticalQueue.get(a).file().getPath()));
    }

    interface Install {
        RulesBundle.Info run() throws Exception;
    }

    /** Install / download a rules set off the UI thread, then report. */
    void installRules(Install job) {
        bg.execute(() -> {
            String msg;
            try {
                RulesBundle.Info i = job.run();
                WatchFilter.criticalActive(a);
                msg = i == null ? a.getString(R.string.rules_up_to_date)
                        : a.getString(R.string.rules_installed_ok, i.manifest.version);
            } catch (Exception e) {
                msg = a.getString(R.string.rules_failed, e.getMessage());
            }
            String m = msg;
            a.runOnUiThread(() -> {
                new AlertDialog.Builder(a).setMessage(m).setPositiveButton(R.string.ok, null).show();
                refreshStores();
            });
        });
    }

    public void installRules(Uri uri) {
        installRules(() -> {
            try (InputStream in = a.getContentResolver().openInputStream(uri)) {
                if (in == null) throw new IOException("cannot open " + uri);
                return RulesBundle.install(a, in, String.valueOf(uri.getLastPathSegment()), null);
            }
        });
    }

    private void askText(int title, int hint, String value, java.util.function.Consumer<String> done) {
        EditText e = new EditText(a);
        e.setHint(hint);
        e.setText(value);
        e.setSingleLine(true);
        int pad = (int) (20 * a.getResources().getDisplayMetrics().density);
        FrameLayout box = new FrameLayout(a);
        box.setPadding(pad, pad / 2, pad, 0);
        box.addView(e);
        new AlertDialog.Builder(a).setTitle(title).setView(box)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.ok, (d, w) -> done.accept(e.getText().toString().trim()))
                .show();
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
