package yara.docscan.android.scan;

import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.os.SystemClock;
import android.provider.OpenableColumns;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The broker side of scanning - the Android counterpart of {@code yara64 --docscan-json docscan-index.yar}.
 *
 * <p>The hostile file is parsed only by {@link IsolatedScanService} (sandboxed process); this class
 * opens the file, hands over the descriptor and gets the JSON back. If the worker dies on a file, the
 * file is reported as ERROR and the worker is started again for the next one.
 *
 * <p>All methods block: call them off the main thread.
 */
public final class DocScanner {
    private static final String TAG = "DocScanner";
    private static final long BIND_TIMEOUT_MS = 20_000;

    private static volatile DocScanner instance;

    private final Context app;
    private final Object lock = new Object();
    private IScanWorker worker;        // guarded by lock
    private boolean bound;             // guarded by lock
    private boolean initialized;       // guarded by lock: the current worker has loaded the rules
    private long criticalStamp = -1;   // guarded by lock: the critical rules the current worker has
    private String version = "?";

    /** What else a scan does besides detection. */
    public static final class Options {
        /** Plan the cure the policy asks for; the cured file goes to {@link #cured}. */
        public boolean planDisarm;
        public File cured;
        /** Where the decompressed VBA code goes (macro store), or null. */
        public File macro;
        /** Where the pass-3 queue line goes, or null = no pass 3. */
        public File critical;
    }

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            synchronized (lock) {
                worker = IScanWorker.Stub.asInterface(service);
                initialized = false;   // a (re)started worker process has no rules yet
                criticalStamp = -1;
                lock.notifyAll();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.w(TAG, "scan worker died");
            synchronized (lock) {
                worker = null;
                initialized = false;
            }
        }
    };

    private DocScanner(Context app) {
        this.app = app;
    }

    /** The shared scanner; the first call compiles the rules and starts the worker. */
    public static DocScanner get(Context context) throws DocScanException {
        checkNotMainThread();
        DocScanner s = instance;
        if (s == null) {
            synchronized (DocScanner.class) {
                s = instance;
                if (s == null) {
                    s = new DocScanner(context.getApplicationContext());
                    s.ensureWorker();
                    instance = s;
                }
            }
        }
        return s;
    }

    public String yaraVersion() {
        return version;
    }

    /** Scans a local file (detection only). */
    public ScanResult scan(File file) throws DocScanException {
        return scan(file, new Options());
    }

    /** Scans a local file and, per the options, plans the cure, extracts the VBA, runs pass 3. */
    public ScanResult scan(File file, Options o) throws DocScanException {
        String parent = file.getParent();
        ParcelFileDescriptor in;
        try {
            in = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (IOException e) {
            throw new DocScanException("cannot open " + file + ": " + e.getMessage(), e);
        }
        ParcelFileDescriptor cured = null, macro = null, critical = null;
        try {
            if (o.planDisarm && o.cured != null) cured = openOut(o.cured);
            if (o.macro != null) macro = openOut(o.macro);
            if (o.critical != null) critical = openOut(o.critical);
        } catch (IOException e) {
            close(in);
            close(cured);
            close(macro);
            throw new DocScanException("cannot create a temp file: " + e.getMessage(), e);
        }
        return scanFd(in, file.getName(), parent == null ? "" : parent, o.planDisarm, cured, macro, critical);
    }

    private static ParcelFileDescriptor openOut(File f) throws IOException {
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_WRITE_ONLY
                | ParcelFileDescriptor.MODE_CREATE | ParcelFileDescriptor.MODE_TRUNCATE);
    }

    /** The critical rules changed: the worker gets them before the next scan. */
    public void reloadCritical() {
        synchronized (lock) {
            criticalStamp = -1;
        }
    }

    /** Scans a document behind a content:// or file:// URI (detection only). */
    public ScanResult scan(Uri uri) throws DocScanException {
        ContentResolver cr = app.getContentResolver();
        String name = displayName(cr, uri);
        ParcelFileDescriptor in;
        try {
            in = cr.openFileDescriptor(uri, "r");
        } catch (IOException | SecurityException e) {
            throw new DocScanException("cannot open " + name + ": " + e.getMessage(), e);
        }
        if (in == null) throw new DocScanException("cannot open " + uri);
        return scanFd(in, name, "", false, null, null, null);
    }

    private ScanResult scanFd(ParcelFileDescriptor in, String name, String dir, boolean plan,
                              ParcelFileDescriptor out, ParcelFileDescriptor macro,
                              ParcelFileDescriptor critical) throws DocScanException {
        try {
            IScanWorker w = ensureWorker();
            Bundle b;
            try {
                b = w.scan(in, name, dir, plan, out, macro, critical);
            } catch (RemoteException e) {
                // DeadObjectException: the parser crashed (or the watchdog killed a hung scan)
                Log.e(TAG, "worker died while scanning " + name, e);
                synchronized (lock) {
                    if (worker == w) {
                        worker = null;
                        initialized = false;
                    }
                }
                return ScanResult.error(name, "parser crashed: the sandboxed worker died on this file");
            }
            String err = b.getString("error");
            byte[] json = b.getByteArray("json");
            if (err != null || json == null) {
                return ScanResult.error(name, err != null ? err : "no result");
            }
            byte[] dex = b.getByteArray("dex");
            byte[] crit = b.getByteArray("critical");
            return ScanResult.parse(name, new String(json, StandardCharsets.UTF_8),
                    dex == null ? null : new String(dex, StandardCharsets.UTF_8),
                    crit == null ? null : new String(crit, StandardCharsets.UTF_8));
        } finally {
            close(in);
            close(out);
            close(macro);
            close(critical);
        }
    }

    /** A connected worker with the rules loaded (binds / restarts it as needed). */
    private IScanWorker ensureWorker() throws DocScanException {
        File rules = RulesStore.ensureCompiled(app);
        synchronized (lock) {
            if (!bound) {
                Intent i = new Intent(app, IsolatedScanService.class);
                if (!app.bindService(i, connection, Context.BIND_AUTO_CREATE)) {
                    throw new DocScanException("cannot start the scan worker");
                }
                bound = true;
            }
            long deadline = SystemClock.elapsedRealtime() + BIND_TIMEOUT_MS;
            while (worker == null) {
                long left = deadline - SystemClock.elapsedRealtime();
                if (left <= 0) throw new DocScanException("scan worker did not start");
                try {
                    lock.wait(left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new DocScanException("interrupted");
                }
            }
            if (!initialized) {
                try (ParcelFileDescriptor pfd =
                             ParcelFileDescriptor.open(rules, ParcelFileDescriptor.MODE_READ_ONLY)) {
                    String v = worker.init(pfd);
                    if (v == null) {
                        // stale or damaged cache: compile again next time
                        rules.delete();
                        throw new DocScanException("the worker could not load the rules");
                    }
                    version = v;
                    initialized = true;
                } catch (IOException | RemoteException e) {
                    worker = null;
                    throw new DocScanException("cannot initialise the scan worker: " + e.getMessage(), e);
                }
            }
            long stamp = CriticalRules.stamp(app);
            if (stamp != criticalStamp) {
                File cr = CriticalRules.compiled(app);
                try (ParcelFileDescriptor pfd = stamp == 0 ? null
                        : ParcelFileDescriptor.open(cr, ParcelFileDescriptor.MODE_READ_ONLY)) {
                    if (!worker.initCritical(pfd)) Log.w(TAG, "the worker could not load the critical rules");
                    criticalStamp = stamp;
                } catch (IOException | RemoteException e) {
                    Log.w(TAG, "critical rules not loaded", e);
                }
            }
            return worker;
        }
    }

    // ------------------------------------------------------------------ helpers

    static String displayName(ContentResolver cr, Uri uri) {
        if ("file".equals(uri.getScheme()) && uri.getLastPathSegment() != null) {
            return uri.getLastPathSegment();
        }
        try (Cursor c = cr.query(uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getString(0);
        } catch (RuntimeException ignored) {
            // some providers do not support the query
        }
        String last = uri.getLastPathSegment();
        return last != null ? last : "document";
    }

    private static void close(ParcelFileDescriptor p) {
        if (p == null) return;
        try {
            p.close();
        } catch (IOException ignored) {
        }
    }

    private static void checkNotMainThread() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("DocScanner blocks: call it off the main thread");
        }
    }
}
