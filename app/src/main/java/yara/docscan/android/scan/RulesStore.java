package yara.docscan.android.scan;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Compiled rules for the worker. The rules ship in assets/rules (from the yara-docscan submodule); on
 * first use they are unpacked and compiled in the app process and saved as files/rules-&lt;version&gt;.yarc.
 * The sandboxed worker cannot open files, so it gets the .yarc as a descriptor.
 */
final class RulesStore {
    private static final String TAG = "RulesStore";
    private static final String RULES_ASSET_DIR = "rules";
    private static final String INDEX = "docscan-index.yar";

    private RulesStore() {}

    /** The compiled rules file, compiling it first when needed (slow: ~2-3 s, off the UI thread). */
    static synchronized File ensureCompiled(Context ctx) throws DocScanException {
        File cache = new File(ctx.getFilesDir(), "rules-" + appVersion(ctx) + ".yarc");
        if (cache.isFile() && cache.length() > 0) return cache;

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
        try {
            File[] old = ctx.getFilesDir().listFiles((d, n) -> n.startsWith("rules-") && n.endsWith(".yarc"));
            if (old != null) for (File f : old) f.delete();
            File tmp = new File(cache.getPath() + ".tmp");
            if (!NativeYara.save(h, tmp.getPath()) || !tmp.renameTo(cache)) {
                throw new DocScanException("cannot save compiled rules");
            }
        } finally {
            NativeYara.destroy(h);   // the app process does not scan: free the ~25 MB
            deleteTree(dir);
        }
        return cache;
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

    static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }
}
