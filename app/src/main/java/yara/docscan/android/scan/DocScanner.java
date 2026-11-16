package yara.docscan.android.scan;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.util.Log;

import org.json.JSONException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * The Android counterpart of {@code yara64 --docscan-json docscan-index.yar <file>}.
 *
 * <p>Rules ship in assets/rules (from the yara-docscan submodule). On first use they are copied to
 * the app's private storage and compiled; the compiled set is cached per app version, so later
 * starts only load it.
 */
public final class DocScanner implements AutoCloseable {
    private static final String TAG = "DocScanner";
    private static final String RULES_ASSET_DIR = "rules";
    private static final String INDEX = "docscan-index.yar";
    private static final int SCAN_TIMEOUT_SEC = 120;

    private static volatile DocScanner instance;

    private long rules;

    private DocScanner(long rules) {
        this.rules = rules;
    }

    /** The shared scanner; the first call compiles or loads the rules (slow: call off the UI thread). */
    public static DocScanner get(Context context) throws DocScanException {
        DocScanner s = instance;
        if (s == null) {
            synchronized (DocScanner.class) {
                s = instance;
                if (s == null) {
                    s = new DocScanner(loadRules(context.getApplicationContext()));
                    instance = s;
                }
            }
        }
        return s;
    }

    public static String yaraVersion() {
        return NativeYara.version();
    }

    private static long loadRules(Context ctx) throws DocScanException {
        long ver = appVersion(ctx);
        File cache = new File(ctx.getFilesDir(), "rules-" + ver + ".yarc");
        if (cache.isFile()) {
            long h = NativeYara.load(cache.getPath());
            if (h != 0) return h;
            Log.w(TAG, "cached rules are unusable, recompiling");
        }

        File dir = new File(ctx.getFilesDir(), "rules-src");
        deleteTree(dir);
        try {
            copyAssetTree(ctx.getAssets(), RULES_ASSET_DIR, dir);
        } catch (IOException e) {
            throw new DocScanException("cannot unpack rules: " + e.getMessage(), e);
        }

        long t0 = System.nanoTime();
        long h = NativeYara.compile(new File(dir, INDEX).getPath());
        Log.i(TAG, "rules compiled in " + (System.nanoTime() - t0) / 1_000_000 + " ms");

        // drop caches of other versions, keep the new one
        File[] old = ctx.getFilesDir().listFiles((d, n) -> n.startsWith("rules-") && n.endsWith(".yarc"));
        if (old != null) for (File f : old) f.delete();
        if (!NativeYara.save(h, cache.getPath())) Log.w(TAG, "cannot cache compiled rules");
        deleteTree(dir);
        return h;
    }

    /** Scans a document behind a content:// or file:// URI. */
    public ScanResult scan(Context context, Uri uri) throws DocScanException {
        ContentResolver cr = context.getContentResolver();
        String name = displayName(cr, uri);
        try (ParcelFileDescriptor pfd = cr.openFileDescriptor(uri, "r")) {
            if (pfd == null) throw new DocScanException("cannot open " + uri);
            return scanFd(pfd.getFd(), name, "");
        } catch (IOException | SecurityException e) {
            throw new DocScanException("cannot open " + name + ": " + e.getMessage(), e);
        }
    }

    /** Scans a local file. */
    public ScanResult scan(File file) throws DocScanException {
        try (ParcelFileDescriptor pfd =
                     ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)) {
            String parent = file.getParent();
            return scanFd(pfd.getFd(), file.getName(), parent == null ? "" : parent);
        } catch (IOException e) {
            throw new DocScanException("cannot open " + file + ": " + e.getMessage(), e);
        }
    }

    private synchronized ScanResult scanFd(int fd, String name, String dir) throws DocScanException {
        if (rules == 0) throw new DocScanException("scanner is closed");
        byte[] json = NativeYara.scanFd(rules, fd, name, dir, SCAN_TIMEOUT_SEC);
        try {
            return ScanResult.parse(name, new String(json, StandardCharsets.UTF_8));
        } catch (JSONException e) {
            throw new DocScanException("bad scan output: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void close() {
        if (rules != 0) {
            NativeYara.destroy(rules);
            rules = 0;
        }
        if (instance == this) instance = null;
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

    private static long appVersion(Context ctx) {
        try {
            return ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0).lastUpdateTime;
        } catch (Exception e) {
            return 0;
        }
    }

    private static void copyAssetTree(AssetManager am, String asset, File target) throws IOException {
        String[] children = am.list(asset);
        if (children == null || children.length == 0) {
            File parent = target.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                throw new IOException("mkdir " + parent);
            }
            try (InputStream in = am.open(asset); OutputStream out = new FileOutputStream(target)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            }
            return;
        }
        if (!target.isDirectory() && !target.mkdirs()) throw new IOException("mkdir " + target);
        for (String c : children) copyAssetTree(am, asset + "/" + c, new File(target, c));
    }

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }
}
