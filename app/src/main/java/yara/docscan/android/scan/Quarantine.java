package yara.docscan.android.scan;

import android.content.Context;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Backups and quarantined files (the -BackupDir of the PC watcher): files/quarantine in the app's
 * private storage, where nothing else can open them. Every copy is "&lt;name&gt;.&lt;n&gt;.docscan-bak" (the
 * naming of disarm.c) with a "&lt;copy&gt;.json" next to it: where it came from, when and why.
 */
public final class Quarantine {
    public static final class Entry {
        public final File copy;
        public final String originalPath;
        public final long time;
        public final String action;    // "removed:vbaProject.bin", "quarantined", ...
        public final String verdict;
        public final String summary;

        Entry(File copy, JSONObject meta) {
            this.copy = copy;
            this.originalPath = meta.optString("original");
            this.time = meta.optLong("time");
            this.action = meta.optString("action");
            this.verdict = meta.optString("verdict");
            this.summary = meta.optString("summary");
        }

        /** The original was replaced by a cured copy (not removed). */
        public boolean isBackupOfCured() {
            return action.startsWith("removed:") || action.startsWith("stripped:") || action.startsWith("broken:");
        }
    }

    private final File dir;

    public Quarantine(Context ctx) {
        this(new File(ctx.getFilesDir(), "quarantine"));
    }

    Quarantine(File dir) {
        this.dir = dir;
    }

    public File dir() {
        return dir;
    }

    /** Copies the file in. Throws when the copy could not be written (then nothing may be changed). */
    File backup(File src) throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("mkdir " + dir);
        File bak;
        int i = 0;
        do {
            bak = new File(dir, src.getName() + "." + (i++) + ".docscan-bak");
        } while (bak.exists() && i < 100000);
        copy(src, bak);
        return bak;
    }

    void writeMeta(File copy, String original, String action, String verdict, String summary) {
        try {
            JSONObject m = new JSONObject()
                    .put("original", original)
                    .put("time", System.currentTimeMillis())
                    .put("action", action)
                    .put("verdict", verdict == null ? "" : verdict)
                    .put("summary", summary == null ? "" : summary);
            try (OutputStream o = new FileOutputStream(new File(copy.getPath() + ".json"))) {
                o.write(m.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {
            // the copy itself is what matters
        }
    }

    public List<Entry> list() {
        List<Entry> out = new ArrayList<>();
        File[] files = dir.listFiles((d, n) -> n.endsWith(".docscan-bak"));
        if (files == null) return out;
        Arrays.sort(files, (a, b) -> Long.compare(b.lastModified(), a.lastModified()));
        for (File f : files) {
            JSONObject meta = new JSONObject();
            File mf = new File(f.getPath() + ".json");
            if (mf.isFile()) {
                try {
                    meta = new JSONObject(new String(readAll(mf), StandardCharsets.UTF_8));
                } catch (Exception ignored) {
                    // a copy without readable metadata is still listed
                }
            }
            out.add(new Entry(f, meta));
        }
        return out;
    }

    /** Puts the copy back at its original path (overwriting the cured file, if any). */
    public void restore(Entry e) throws IOException {
        File target = new File(e.originalPath);
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) throw new IOException("mkdir " + parent);
        copy(e.copy, target);
        delete(e);
    }

    public void delete(Entry e) {
        e.copy.delete();
        new File(e.copy.getPath() + ".json").delete();
    }

    static void copy(File src, File dst) throws IOException {
        try (InputStream in = new FileInputStream(src); OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            out.flush();
        } catch (IOException e) {
            dst.delete();
            throw e;
        }
    }

    private static byte[] readAll(File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            byte[] b = new byte[(int) f.length()];
            int off = 0, n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            return b;
        }
    }
}
