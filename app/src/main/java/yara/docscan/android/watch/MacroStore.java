package yara.docscan.android.watch;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The macro store of docscan-watcher.ps1 (Save-Macro / Send-Macro / Sync-Macros):
 * files/macros/&lt;document sha256&gt;.vba.txt, one file per document content. The file starts with a short
 * header (VBA comment lines: host, document path, sha256, findings, time) so a copy on the collector
 * is self-describing, then the VBA code. Sent files are listed in sent.txt; the rest is retried.
 */
public final class MacroStore {
    private static final String TAG = "MacroStore";
    static final int KEEP_DAYS = 90;       // -MacroKeepDays
    static final long MAX_BYTES = 500L * 1024 * 1024;   // -MacroMaxMB
    /** VBA source is stored in the project's ANSI code page; on Ukrainian / Russian PCs that is 1251. */
    private static final Charset FALLBACK = Charset.forName("windows-1251");

    private final File dir;
    private final File sentFile;
    private final Set<String> sent = new HashSet<>();

    public MacroStore(Context ctx) {
        this(new File(ctx.getFilesDir(), "macros"));
    }

    public MacroStore(File dir) {
        this.dir = dir;
        this.sentFile = new File(dir, "sent.txt");
        loadSent();
    }

    public File dir() {
        return dir;
    }

    public int count() {
        File[] f = dir.listFiles((d, n) -> n.endsWith(".vba.txt"));
        return f == null ? 0 : f.length;
    }

    /**
     * Save-Macro: the decompressed VBA in {@code tmp} -> &lt;sha&gt;.vba.txt with the header. A document with
     * the same content is stored once. Returns the stored file, or null when there is no code.
     */
    public synchronized File save(String docSha, File tmp, String host, String path, List<String> findings) {
        if (tmp == null || !tmp.isFile() || tmp.length() == 0 || docSha == null) return null;
        File dst = new File(dir, docSha + ".vba.txt");
        if (dst.isFile()) return dst;
        if (!dir.isDirectory() && !dir.mkdirs()) return null;
        try {
            byte[] raw = readAll(tmp);
            String hdr = "' DocScan macro\r\n' host: " + host + "\r\n' file: " + path + "\r\n' sha256: " + docSha
                    + "\r\n' findings: " + String.join(", ", findings) + "\r\n' saved: "
                    + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT).format(new Date()) + "\r\n'\r\n";
            try (OutputStream o = new FileOutputStream(dst)) {
                o.write((hdr + decode(raw)).getBytes(StandardCharsets.UTF_8));
            }
            return dst;
        } catch (IOException e) {
            dst.delete();
            Log.w(TAG, "cannot store the macro of " + path, e);
            return null;
        }
    }

    /** Valid UTF-8 (or ASCII) is kept as it is, anything else is decoded as windows-1251. */
    static String decode(byte[] raw) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            return new String(raw, FALLBACK);
        }
    }

    /** Send-Macro: POST the stored file to the collector (application/octet-stream). */
    public synchronized boolean send(File file, String url) {
        if (url == null || url.isEmpty() || file == null) return false;
        String sha = file.getName().replace(".vba.txt", "");
        if (sent.contains(sha)) return true;
        HttpURLConnection c = null;
        try {
            byte[] body = readAll(file);
            c = (HttpURLConnection) new URL(url.replaceAll("/+$", "") + "/").openConnection();
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setConnectTimeout(15_000);
            c.setReadTimeout(15_000);
            c.setRequestProperty("Content-Type", "application/octet-stream");
            c.setFixedLengthStreamingMode(body.length);
            try (OutputStream o = c.getOutputStream()) {
                o.write(body);
            }
            int code = c.getResponseCode();
            if (code < 200 || code >= 300) throw new IOException("HTTP " + code);
            sent.add(sha);
            try (OutputStream o = new FileOutputStream(sentFile, true)) {
                o.write((sha + "\r\n").getBytes(StandardCharsets.UTF_8));
            }
            return true;
        } catch (IOException e) {
            Log.w(TAG, "macro upload failed (will retry): " + file.getName() + " - " + e.getMessage());
            return false;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /** Sync-Macros: retention (age, total size; oldest first) and the upload retry. */
    public synchronized void sync(String url) {
        File[] files = dir.listFiles((d, n) -> n.endsWith(".vba.txt"));
        if (files == null) return;
        Arrays.sort(files, (a, b) -> Long.compare(a.lastModified(), b.lastModified()));
        long limit = System.currentTimeMillis() - KEEP_DAYS * 24L * 3600 * 1000;
        long total = 0;
        for (File f : files) total += f.length();
        Set<String> kept = new HashSet<>();
        for (File f : files) {
            if (f.lastModified() < limit || total > MAX_BYTES) {
                total -= f.length();
                f.delete();
            } else {
                kept.add(f.getName().replace(".vba.txt", ""));
            }
        }
        // sent.txt keeps only the files that are still in the store
        if (sent.retainAll(kept)) {
            try (OutputStream o = new FileOutputStream(sentFile)) {
                for (String s : sent) o.write((s + "\r\n").getBytes(StandardCharsets.UTF_8));
            } catch (IOException ignored) {
                // rewritten next time
            }
        }
        if (url == null || url.isEmpty()) return;
        for (File f : files) {
            if (!f.isFile() || sent.contains(f.getName().replace(".vba.txt", ""))) continue;
            if (!send(f, url)) break;
            try {
                Thread.sleep(1100);   // the collector names files <ip>_<yyyyMMdd_HHmmss>.txt
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    public synchronized boolean isSent(File f) {
        return sent.contains(f.getName().replace(".vba.txt", ""));
    }

    private void loadSent() {
        if (!sentFile.isFile()) return;
        try {
            for (String l : new String(readAll(sentFile), StandardCharsets.UTF_8).split("\\r?\\n")) {
                if (!l.trim().isEmpty()) sent.add(l.trim());
            }
        } catch (IOException ignored) {
            // start with an empty list: at worst a file is sent twice
        }
    }

    private static byte[] readAll(File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            byte[] b = new byte[(int) f.length()];
            int off = 0, n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            return off == b.length ? b : Arrays.copyOf(b, off);
        }
    }
}
