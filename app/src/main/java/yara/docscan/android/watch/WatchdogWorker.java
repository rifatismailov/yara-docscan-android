package yara.docscan.android.watch;

import android.content.Context;
import android.content.Intent;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import yara.docscan.android.scan.RulesBundle;

import java.util.concurrent.TimeUnit;

/**
 * Every 15 minutes: bring the watcher back if the system (or an aggressive vendor battery saver)
 * killed it, and ask for the catch-up sweep every few hours.
 */
public class WatchdogWorker extends Worker {
    private static final String NAME = "docscan-watchdog";

    public WatchdogWorker(@NonNull Context ctx, @NonNull WorkerParameters params) {
        super(ctx, params);
    }

    public static void schedule(Context ctx) {
        PeriodicWorkRequest req = new PeriodicWorkRequest.Builder(WatchdogWorker.class, 15, TimeUnit.MINUTES).build();
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, req);
    }

    @NonNull
    @Override
    public Result doWork() {
        Context ctx = getApplicationContext();
        WatchSettings s = new WatchSettings(ctx);
        if (!s.enabled()) return Result.success();
        // rules update from the configured URL, once a day (installed only when it changed)
        String url = s.rulesUrl();
        if (!url.isEmpty() && System.currentTimeMillis() - s.lastRulesCheck() > 24L * 3600 * 1000) {
            try {
                RulesBundle.Info i = RulesBundle.installFromUrl(ctx, url, true);
                s.setLastRulesCheck(System.currentTimeMillis());
                if (i != null) {
                    android.util.Log.i("WatchdogWorker", "rules updated to " + i.manifest.version);
                    WatchFilter.criticalActive(ctx);
                }
            } catch (Exception e) {
                android.util.Log.w("WatchdogWorker", "rules update failed: " + e.getMessage());
            }
        }
        // Sync-Macros: retention + upload retry, once an hour
        if (System.currentTimeMillis() - s.lastMacroSync() > 3600_000L) {
            s.setLastMacroSync(System.currentTimeMillis());
            new MacroStore(ctx).sync(s.macroUploadUrl());
        }
        boolean due = System.currentTimeMillis() - s.lastCatchUp() > WatcherService.CATCH_UP_EVERY_MS;
        if (!WatcherService.running || due) {
            Intent i = new Intent(ctx, WatcherService.class);
            if (due && WatcherService.running) i.setAction(WatcherService.ACTION_CATCH_UP);
            try {
                ContextCompat.startForegroundService(ctx, i);
            } catch (RuntimeException e) {
                // Android 12+: not allowed from the background unless exempt from battery optimisation
                return Result.retry();
            }
        }
        return Result.success();
    }
}
