package yara.docscan.android.watch;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import androidx.core.content.ContextCompat;

import java.io.File;
import java.util.ArrayDeque;

import yara.docscan.android.R;
import yara.docscan.android.device.DeviceMonitor;
import yara.docscan.android.scan.DocScanner;

/**
 * The file watcher (docscan-watcher.ps1 on Android): a foreground service that watches the shared
 * storage, new / updated apps and the security settings, and scans in the sandboxed worker.
 */
public class WatcherService extends Service implements RecursiveObserver.Listener {
    private static final String TAG = "WatcherService";
    public static final String ACTION_CATCH_UP = "yara.docscan.android.CATCH_UP";
    /** A full catch-up sweep at most this often (the WatchdogWorker asks for it). */
    static final long CATCH_UP_EVERY_MS = 6L * 3600 * 1000;

    /** For the UI. */
    public static volatile boolean running;
    public static volatile int watchedDirs;
    public static volatile boolean watchLimitReached;
    public static volatile String status = "";

    private final Handler main = new Handler(Looper.getMainLooper());
    private ScanQueue queue;
    private ScanPipeline pipeline;
    private RecursiveObserver observer;
    private MediaStoreWatcher mediaStore;
    private DeviceMonitor device;
    private File root;
    private int scanned;
    private long lastNotify;

    private final BroadcastReceiver packages = new BroadcastReceiver() {
        @Override
        public void onReceive(Context c, Intent i) {
            if (i.getData() == null) return;
            String pkg = i.getData().getSchemeSpecificPart();
            boolean replacing = i.getBooleanExtra(Intent.EXTRA_REPLACING, false);
            if (Intent.ACTION_PACKAGE_ADDED.equals(i.getAction()) && replacing) return;   // REPLACED follows
            queue.app(pkg, Intent.ACTION_PACKAGE_REPLACED.equals(i.getAction()) ? "Updated" : "Installed");
        }
    };

    public static void start(Context ctx) {
        new WatchSettings(ctx).setEnabled(true);
        ContextCompat.startForegroundService(ctx, new Intent(ctx, WatcherService.class));
    }

    public static void stop(Context ctx) {
        new WatchSettings(ctx).setEnabled(false);
        ctx.stopService(new Intent(ctx, WatcherService.class));
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Notifier.createChannels(this);
        status = getString(R.string.service_starting);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(Notifier.ID_SERVICE, Notifier.service(this, status),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(Notifier.ID_SERVICE, Notifier.service(this, status));
        }
        running = true;

        pipeline = new ScanPipeline(this);
        queue = new ScanQueue(pipeline);
        pipeline.setListener((subject, verdict) -> main.post(() -> {
            scanned++;
            updateStatus();
        }));

        root = Environment.getExternalStorageDirectory();
        WatchFilter.setCriticalOn(yara.docscan.android.scan.CriticalRules.isOn(this));
        // rules + worker first, then the watches (both can take a few seconds)
        queue.submit(() -> {
            try {
                DocScanner.get(this);
            } catch (Exception e) {
                Log.e(TAG, "scanner start failed", e);
                status = getString(R.string.rules_failed, e.getMessage());
                main.post(() -> Notifier.updateService(this, status));
            }
        });
        new Thread(this::startWatching, "docscan-watch-start").start();

        IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_PACKAGE_ADDED);
        f.addAction(Intent.ACTION_PACKAGE_REPLACED);
        f.addDataScheme("package");
        ContextCompat.registerReceiver(this, packages, f, ContextCompat.RECEIVER_EXPORTED);

        device = DeviceMonitor.start(this, ScanPipeline.hostName(this));
        WatchdogWorker.schedule(this);
    }

    private void startWatching() {
        observer = new RecursiveObserver(root, this);
        observer.start();
        watchedDirs = observer.count();
        watchLimitReached = observer.isFull();
        mediaStore = MediaStoreWatcher.start(this, f -> {
            if (!WatchFilter.isExcluded(observer.relative(f))) queue.fileEvent(f, "Changed");
        });
        main.post(this::updateStatus);
        // always: whatever arrived while the service was not running (killed, reboot, update) has
        // produced no events; unchanged files are skipped by the index, so this is cheap
        catchUp();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_CATCH_UP.equals(intent.getAction()) && observer != null) {
            new Thread(this::catchUp, "docscan-catch-up").start();
        }
        return START_STICKY;
    }

    /** The full sweep: every file the watcher would scan, skipped when unchanged since its last scan. */
    private void catchUp() {
        new WatchSettings(this).setLastCatchUp(System.currentTimeMillis());
        catchUpApps();
        ArrayDeque<File> q = new ArrayDeque<>();
        q.add(root);
        int n = 0;
        while (!q.isEmpty()) {
            File d = q.poll();
            File[] kids = d.listFiles();
            if (kids == null) continue;
            for (File k : kids) {
                if (WatchFilter.isExcluded(observer.relative(k))) continue;
                if (k.isDirectory()) q.add(k);
                else if (WatchFilter.category(k.getName()) != null) {
                    queue.rescan(k);
                    n++;
                }
            }
        }
        if (device != null) device.checkNow();
        Log.i(TAG, "catch-up: " + n + " candidate files");
    }

    private void catchUpApps() {
        for (String pkg : pipeline.changedApps()) queue.app(pkg, "Rescan");
    }

    @Override
    public void onFile(File f, String event) {
        if (WatchFilter.category(f.getName()) != null) queue.fileEvent(f, event);
    }

    @Override
    public void onNewDirectory(File dir) {
        // a directory moved in (or unpacked) with files in it: they produce no events of their own
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File k : kids) {
            if (k.isDirectory()) onNewDirectory(k);
            else onFile(k, "Created");
        }
    }

    private void updateStatus() {
        int backlog = queue.backlog();
        status = getString(R.string.service_status, watchedDirs, scanned)
                + (backlog > 1 ? getString(R.string.service_backlog, backlog) : "");
        long now = System.currentTimeMillis();
        if (now - lastNotify > 2000 || backlog <= 1) {   // do not flood the notification during a sweep
            lastNotify = now;
            Notifier.updateService(this, status);
        }
    }

    @Override
    public void onDestroy() {
        running = false;
        try {
            unregisterReceiver(packages);
        } catch (IllegalArgumentException ignored) {
            // not registered
        }
        if (observer != null) observer.stop();
        if (mediaStore != null) mediaStore.stop();
        if (device != null) device.stop();
        if (queue != null) queue.shutdown();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
