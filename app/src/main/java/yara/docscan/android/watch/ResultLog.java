package yara.docscan.android.watch;

import android.content.Context;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * docscan-results.json of the PC watcher: one JSON line per scanned file, the same fields, for the SIEM
 * (sending it out is the next step). Rotation file -> file.1 -> ... -> file.KEEP; a record identical to
 * the last one for the same path (verdict + summary) is not written again, except HIGH.
 */
public final class ResultLog {
    private static final long MAX_BYTES = 50L * 1024 * 1024;   // -MaxLogMB
    private static final int KEEP = 5;                          // -KeepLogs

    private static volatile ResultLog instance;

    private final File file;
    private final Map<String, String> lastKey = new HashMap<>();

    public static ResultLog get(Context ctx) {
        ResultLog l = instance;
        if (l == null) {
            synchronized (ResultLog.class) {
                l = instance;
                if (l == null) {
                    instance = l = new ResultLog(new File(new File(ctx.getFilesDir(), "results"), "docscan-results.json"));
                }
            }
        }
        return l;
    }

    ResultLog(File file) {
        this.file = file;
    }

    public File file() {
        return file;
    }

    /** @return false when the record repeats the last one for this subject and was not written */
    public synchronized boolean append(String subject, JSONObject rec) {
        String verdict = rec.optString("verdict");
        String key = verdict + "|" + rec.optString("summary");
        if (!"HIGH".equals(verdict) && key.equals(lastKey.get(subject))) return false;
        File dir = file.getParentFile();
        if (dir != null && !dir.isDirectory()) dir.mkdirs();
        rotateIfBig();
        try (OutputStream o = new FileOutputStream(file, true)) {
            o.write((rec.toString() + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return false;
        }
        lastKey.put(subject, key);
        return true;
    }

    private void rotateIfBig() {
        if (!file.isFile() || file.length() < MAX_BYTES) return;
        for (int k = KEEP - 1; k >= 1; k--) {
            File from = new File(file.getPath() + "." + k);
            if (from.exists()) from.renameTo(new File(file.getPath() + "." + (k + 1)));
        }
        file.renameTo(new File(file.getPath() + ".1"));
    }
}
