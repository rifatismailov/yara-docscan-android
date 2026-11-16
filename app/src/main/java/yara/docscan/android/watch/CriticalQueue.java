package yara.docscan.android.watch;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The E5Search queue of pass 3 (critical\critical.json of the PC watcher): one JSON line (schema 2.0)
 * per matching document, appended in one write; the sender takes the file by renaming it. The same
 * document content is queued once ($CritQueued).
 */
public final class CriticalQueue {
    private static volatile CriticalQueue instance;
    private final File file;
    private final Set<String> queued = Collections.synchronizedSet(new LinkedHashSet<>());

    public static CriticalQueue get(Context ctx) {
        CriticalQueue q = instance;
        if (q == null) {
            synchronized (CriticalQueue.class) {
                q = instance;
                if (q == null) instance = q = new CriticalQueue(new File(new File(ctx.getFilesDir(), "critical"), "critical.json"));
            }
        }
        return q;
    }

    CriticalQueue(File file) {
        this.file = file;
    }

    public File file() {
        return file;
    }

    /** Pass 3 not run yet for this content. */
    public boolean isNew(String sha) {
        return sha != null && !queued.contains(sha);
    }

    /** Appends the line the worker wrote to {@code line}. */
    public synchronized boolean append(String sha, File line) {
        if (line == null || !line.isFile() || line.length() == 0) return false;
        File dir = file.getParentFile();
        if (dir != null && !dir.isDirectory()) dir.mkdirs();
        try (InputStream in = new FileInputStream(line)) {
            byte[] b = new byte[(int) line.length()];
            int off = 0, n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            try (OutputStream o = new FileOutputStream(file, true)) {
                o.write(b, 0, off);   // one write
            }
        } catch (IOException e) {
            return false;
        }
        if (queued.size() > 20000) queued.clear();
        if (sha != null) queued.add(sha);
        return true;
    }
}
