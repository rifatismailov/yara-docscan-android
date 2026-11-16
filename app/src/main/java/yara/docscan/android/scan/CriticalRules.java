package yara.docscan.android.scan;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * The critical-information rules of pass 3 (the -Critical &lt;file or URL&gt; of the PC installer): they come
 * from E5Search, are not part of the release and are imported on the device. Kept as source
 * (files/critical/rules.yar) and compiled (rules.yarc) for the sandboxed worker. No rules = pass 3 off.
 */
public final class CriticalRules {
    private static final long MAX_BYTES = 64L * 1024 * 1024;

    private CriticalRules() {}

    static File dir(Context ctx) {
        return new File(ctx.getFilesDir(), "critical");
    }

    static File source(Context ctx) {
        return new File(dir(ctx), "rules.yar");
    }

    static File compiled(Context ctx) {
        return new File(dir(ctx), "rules.yarc");
    }

    public static boolean isOn(Context ctx) {
        return compiled(ctx).isFile();
    }

    /** Changes whenever the rules change (the worker reloads them). 0 = none. */
    static long stamp(Context ctx) {
        File f = compiled(ctx);
        return f.isFile() ? f.lastModified() ^ f.length() : 0;
    }

    /** Where the rules came from (file name or URL), for the UI. */
    public static String origin(Context ctx) {
        File f = new File(dir(ctx), "origin.txt");
        try (InputStream in = new java.io.FileInputStream(f)) {
            return new String(readAll(in, 4096), "UTF-8");
        } catch (IOException e) {
            return "";
        }
    }

    /**
     * Compiles the rules and makes them current. On a compile error the previous rules stay.
     * Blocking (off the main thread).
     */
    public static synchronized void install(Context ctx, InputStream in, String origin) throws DocScanException {
        File d = dir(ctx);
        if (!d.isDirectory() && !d.mkdirs()) throw new DocScanException("mkdir " + d);
        File src = new File(d, "rules.new.yar");
        try (OutputStream o = new FileOutputStream(src)) {
            o.write(readAll(in, MAX_BYTES));
        } catch (IOException e) {
            throw new DocScanException("cannot read the rules: " + e.getMessage(), e);
        }
        long h = NativeYara.compile(src.getPath());   // throws with the compiler messages
        try {
            File tmp = new File(d, "rules.yarc.tmp");
            if (!NativeYara.save(h, tmp.getPath()) || !tmp.renameTo(compiled(ctx))) {
                throw new DocScanException("cannot save the compiled rules");
            }
        } finally {
            NativeYara.destroy(h);
        }
        src.renameTo(source(ctx));
        try (OutputStream o = new FileOutputStream(new File(d, "origin.txt"))) {
            o.write(origin.getBytes("UTF-8"));
        } catch (IOException ignored) {
            // cosmetic
        }
    }

    /** Downloads the rules from a URL (http/https) and installs them. */
    public static void installFromUrl(Context ctx, String url) throws DocScanException {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(15_000);
            c.setReadTimeout(30_000);
            if (c.getResponseCode() != 200) throw new DocScanException("HTTP " + c.getResponseCode());
            try (InputStream in = c.getInputStream()) {
                install(ctx, in, url);
            }
        } catch (IOException e) {
            throw new DocScanException("cannot download " + url + ": " + e.getMessage(), e);
        } finally {
            if (c != null) c.disconnect();
        }
    }

    public static synchronized void remove(Context ctx) {
        compiled(ctx).delete();
        source(ctx).delete();
        new File(dir(ctx), "origin.txt").delete();
    }

    private static byte[] readAll(InputStream in, long max) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[64 * 1024];
        long n = 0;
        int r;
        while ((r = in.read(buf)) > 0) {
            n += r;
            if (n > max) throw new IOException("larger than " + max / (1024 * 1024) + " MB");
            bo.write(buf, 0, r);
        }
        return bo.toByteArray();
    }
}
