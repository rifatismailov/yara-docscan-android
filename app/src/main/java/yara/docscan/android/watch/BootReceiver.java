package yara.docscan.android.watch;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import androidx.core.content.ContextCompat;

/** Starts the watcher after a reboot and after an update of DocScan itself, if protection is on. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent intent) {
        String a = intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(a) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)
                && !"android.intent.action.QUICKBOOT_POWERON".equals(a)) {
            return;
        }
        if (!new WatchSettings(ctx).enabled()) return;
        try {
            ContextCompat.startForegroundService(ctx, new Intent(ctx, WatcherService.class));
        } catch (RuntimeException ignored) {
            // the watchdog worker retries
        }
        WatchdogWorker.schedule(ctx);
    }
}
