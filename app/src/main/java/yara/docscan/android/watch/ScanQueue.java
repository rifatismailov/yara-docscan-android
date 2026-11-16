package yara.docscan.android.watch;

import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Debouncing in front of the pipeline, as in docscan-watcher.ps1: a file is scanned after
 * -SettleSeconds of quiet, the same path at most once per -RescanCooldown, and the events caused by
 * our own cure are ignored. One scan thread (low priority): files, apps and sweeps go one by one.
 */
public final class ScanQueue implements ScanPipeline.Suppressor {
    private static final String TAG = "ScanQueue";
    static final long SETTLE_MS = 2_000;        // -SettleSeconds
    static final long COOLDOWN_MS = 60_000;     // -RescanCooldown
    static final long SUPPRESS_MS = 5_000;

    private final ScanPipeline pipeline;
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(() -> {
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
            r.run();
        }, "docscan-scan");
        t.setDaemon(true);
        return t;
    });

    private final Object lock = new Object();
    private final Map<String, ScheduledFuture<?>> pending = new HashMap<>();
    private final Map<String, Long> lastScan = new HashMap<>();
    private final Map<String, Long> suppressUntil = new HashMap<>();
    private final AtomicInteger backlog = new AtomicInteger();

    public ScanQueue(ScanPipeline pipeline) {
        this.pipeline = pipeline;
        pipeline.setSuppressor(this);
    }

    /** Number of jobs waiting or running. */
    public int backlog() {
        return backlog.get();
    }

    /** A file system event: (re)start the settle timer of the path. */
    public void fileEvent(File f, String event) {
        String path = f.getPath();
        synchronized (lock) {
            Long until = suppressUntil.get(path);
            if (until != null) {
                if (SystemClock.elapsedRealtime() < until) return;
                suppressUntil.remove(path);
            }
            ScheduledFuture<?> old = pending.remove(path);
            if (old != null) old.cancel(false);
            pending.put(path, timer.schedule(() -> due(f, event), SETTLE_MS, TimeUnit.MILLISECONDS));
        }
    }

    private void due(File f, String event) {
        String path = f.getPath();
        synchronized (lock) {
            pending.remove(path);
            Long last = lastScan.get(path);
            long now = SystemClock.elapsedRealtime();
            if (last != null && now - last < COOLDOWN_MS) {
                // the same file again too soon (autosave): scan once more when the cooldown ends
                pending.put(path, timer.schedule(() -> due(f, event), last + COOLDOWN_MS - now, TimeUnit.MILLISECONDS));
                return;
            }
            lastScan.put(path, now);
            if (lastScan.size() > 5000) lastScan.clear();
        }
        submit(() -> pipeline.scanFile(f, event, false));
    }

    /** A sweep / catch-up file: no settle time, skipped when unchanged since the last scan. */
    public void rescan(File f) {
        submit(() -> pipeline.scanFile(f, "Rescan", false));
    }

    public void app(String pkg, String event) {
        submit(() -> pipeline.scanApp(pkg, event));
    }

    public void submit(Runnable job) {
        backlog.incrementAndGet();
        worker.execute(() -> {
            try {
                job.run();
            } catch (Throwable t) {
                Log.e(TAG, "scan job failed", t);
            } finally {
                backlog.decrementAndGet();
            }
        });
    }

    @Override
    public void suppress(String path) {
        synchronized (lock) {
            suppressUntil.put(path, SystemClock.elapsedRealtime() + SUPPRESS_MS);
        }
    }

    public void shutdown() {
        timer.shutdownNow();
        worker.shutdownNow();
    }
}
