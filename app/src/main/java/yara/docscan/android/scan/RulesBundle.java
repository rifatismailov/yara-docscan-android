package yara.docscan.android.scan;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * A rules update: one ZIP with the rule files in sub-folders and manifest.json saying what is what.
 *
 * <pre>
 * {
 *   "bundle": "docscan-rules",
 *   "version": "2026.11.17-1",
 *   "description": "...",                                        (optional)
 *   "critical_information": "critical/yara_sender_critical_rules.yar",   (string or list; pass 3)
 *   "detection": "detection/docscan-index.yar",                 (string or list; optional: replaces
 *                                                                 the built-in docscan rules)
 *   "critical_chunk": {"size": 700, "overlap": 120},            (optional: default chunking)
 *   "files": {"critical/yara_sender_critical_rules.yar": "&lt;sha256&gt;", ...}   (optional integrity)
 * }
 * </pre>
 *
 * Installing: unpack into a staging folder (no path may leave it), check the hashes, compile every rule
 * set, and only then swap it in for the current set - a broken update leaves the previous rules.
 */
public final class RulesBundle {
    private static final String TAG = "RulesBundle";
    public static final String MANIFEST = "manifest.json";
    static final long MAX_TOTAL = 256L * 1024 * 1024;
    static final int MAX_FILES = 20000;

    /** manifest.json */
    public static final class Manifest {
        public String version = "";
        public String description = "";
        public final List<String> detection = new ArrayList<>();
        public final List<String> critical = new ArrayList<>();
        public final Map<String, String> sha256 = new HashMap<>();
        public int chunkSize;          // 0 = rule meta / 700
        public int chunkOverlap = -1;  // -1 = rule meta / 120
    }

    /** The installed set. */
    public static final class Info {
        public final Manifest manifest;
        public final String origin;
        public final long installedAt;

        Info(Manifest m, String origin, long installedAt) {
            this.manifest = m;
            this.origin = origin;
            this.installedAt = installedAt;
        }
    }

    private RulesBundle() {}

    // ------------------------------------------------------------------ paths

    static File root(Context ctx) {
        return new File(ctx.getFilesDir(), "bundle");
    }

    static File current(Context ctx) {
        return new File(root(ctx), "current");
    }

    /** Compiled detection rules of the installed set, or null (then the built-in rules are used). */
    public static File detectionRules(Context ctx) {
        File f = new File(current(ctx), "compiled/detection.yarc");
        return f.isFile() ? f : null;
    }

    /** Compiled critical-information rules of the installed set, or null. */
    public static File criticalRules(Context ctx) {
        File f = new File(current(ctx), "compiled/critical.yarc");
        return f.isFile() ? f : null;
    }

    static long stamp(File f) {
        return f == null ? 0 : (f.getPath().hashCode() * 31L) ^ f.lastModified() ^ (f.length() << 20);
    }

    public static Info info(Context ctx) {
        File cur = current(ctx);
        try {
            Manifest m = parseManifest(read(new File(cur, MANIFEST)));
            JSONObject meta = new JSONObject(read(new File(cur, "installed.json")));
            return new Info(m, meta.optString("origin"), meta.optLong("time"));
        } catch (IOException | JSONException | DocScanException e) {
            return null;
        }
    }

    // ------------------------------------------------------------ install

    /** Unpack, check, compile, swap in. Blocking (off the main thread). */
    public static synchronized Info install(Context ctx, InputStream zip, String origin, String etag)
            throws DocScanException {
        File root = root(ctx);
        File staging = new File(root, "staging");
        RulesStore.deleteTree(staging);
        if (!staging.mkdirs()) throw new DocScanException("mkdir " + staging);
        try {
            Manifest m = extract(zip, staging);
            File compiled = new File(staging, "compiled");
            if (!compiled.mkdirs()) throw new DocScanException("mkdir " + compiled);
            if (!m.detection.isEmpty()) compile(staging, m.detection, new File(compiled, "detection.yarc"), "detection");
            if (!m.critical.isEmpty()) compile(staging, m.critical, new File(compiled, "critical.yarc"), "critical_information");
            JSONObject meta = new JSONObject()
                    .put("origin", origin)
                    .put("time", System.currentTimeMillis())
                    .put("etag", etag == null ? "" : etag);
            write(new File(staging, "installed.json"), meta.toString());

            // swap: current -> old, staging -> current
            File cur = current(ctx);
            File old = new File(root, "old");
            RulesStore.deleteTree(old);
            if (cur.exists() && !cur.renameTo(old)) throw new DocScanException("cannot replace the current rules");
            if (!staging.renameTo(cur)) {
                old.renameTo(cur);
                throw new DocScanException("cannot install the rules");
            }
            RulesStore.deleteTree(old);
            Log.i(TAG, "installed rules " + m.version + " from " + origin);
            return new Info(m, origin, meta.optLong("time"));
        } catch (JSONException | IOException e) {
            throw new DocScanException(e.getMessage(), e);
        } finally {
            RulesStore.deleteTree(staging);
        }
    }

    /**
     * Downloads the archive and installs it. With {@code onlyIfChanged}, an unchanged archive (same
     * ETag, or the same manifest version) is not installed again; returns null then.
     */
    public static Info installFromUrl(Context ctx, String url, boolean onlyIfChanged) throws DocScanException {
        String etag = "";
        Info cur = info(ctx);
        if (onlyIfChanged && cur != null && url.equals(cur.origin)) {
            try {
                etag = new JSONObject(read(new File(current(ctx), "installed.json"))).optString("etag");
            } catch (IOException | JSONException ignored) {
                // no etag: download
            }
        }
        HttpURLConnection c = null;
        File tmp = new File(ctx.getCacheDir(), "rules-download.zip");
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(15_000);
            c.setReadTimeout(60_000);
            if (!etag.isEmpty()) c.setRequestProperty("If-None-Match", etag);
            int code = c.getResponseCode();
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) return null;
            if (code != 200) throw new DocScanException("HTTP " + code);
            try (InputStream in = c.getInputStream(); OutputStream o = new FileOutputStream(tmp)) {
                copy(in, o, MAX_TOTAL);
            }
            String newEtag = c.getHeaderField("ETag");
            if (onlyIfChanged && cur != null) {
                Manifest peek = peekManifest(tmp);
                if (peek != null && peek.version.equals(cur.manifest.version)) return null;
            }
            try (InputStream in = new FileInputStream(tmp)) {
                return install(ctx, in, url, newEtag);
            }
        } catch (IOException e) {
            throw new DocScanException("cannot download " + url + ": " + e.getMessage(), e);
        } finally {
            if (c != null) c.disconnect();
            tmp.delete();
        }
    }

    public static synchronized void remove(Context ctx) {
        RulesStore.deleteTree(current(ctx));
    }

    // ------------------------------------------------- pure (JVM-tested)

    /** Unpacks the archive into dir and checks it against its manifest. */
    static Manifest extract(InputStream zip, File dir) throws DocScanException {
        String base;
        try {
            base = dir.getCanonicalPath() + File.separator;
        } catch (IOException e) {
            throw new DocScanException(e.getMessage(), e);
        }
        long total = 0;
        int files = 0;
        try (ZipInputStream z = new ZipInputStream(zip)) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                String name = e.getName().replace('\\', '/');
                File out = new File(dir, name);
                if (!out.getCanonicalPath().startsWith(base) || name.startsWith("/")) {
                    throw new DocScanException("bad path in the archive: " + name);   // zip slip
                }
                if (e.isDirectory()) {
                    if (!out.isDirectory() && !out.mkdirs()) throw new DocScanException("mkdir " + name);
                    continue;
                }
                if (++files > MAX_FILES) throw new DocScanException("too many files in the archive");
                File parent = out.getParentFile();
                if (parent != null && !parent.isDirectory() && !parent.mkdirs()) throw new DocScanException("mkdir " + parent);
                try (OutputStream o = new FileOutputStream(out)) {
                    total += copy(z, o, MAX_TOTAL - total);
                }
            }
        } catch (IOException e) {
            throw new DocScanException("bad archive: " + e.getMessage(), e);
        }
        File mf = new File(dir, MANIFEST);
        if (!mf.isFile()) throw new DocScanException("no " + MANIFEST + " in the archive");
        Manifest m;
        try {
            m = parseManifest(read(mf));
        } catch (IOException e) {
            throw new DocScanException(e.getMessage(), e);
        }
        List<String> all = new ArrayList<>(m.detection);
        all.addAll(m.critical);
        for (String rel : all) {
            if (!new File(dir, rel).isFile()) throw new DocScanException("the manifest names a missing file: " + rel);
        }
        for (Map.Entry<String, String> h : m.sha256.entrySet()) {
            File f = new File(dir, h.getKey());
            if (!f.isFile()) throw new DocScanException("the manifest names a missing file: " + h.getKey());
            String got = sha256(f);
            if (!got.equalsIgnoreCase(h.getValue())) throw new DocScanException("sha256 mismatch: " + h.getKey());
        }
        return m;
    }

    static Manifest parseManifest(String json) throws DocScanException {
        try {
            JSONObject o = new JSONObject(json);
            Manifest m = new Manifest();
            m.version = o.optString("version", "");
            m.description = o.optString("description", "");
            if (m.version.isEmpty()) throw new DocScanException("manifest: \"version\" is required");
            paths(o.opt("detection"), m.detection, "detection");
            paths(o.opt("critical_information"), m.critical, "critical_information");
            if (m.detection.isEmpty() && m.critical.isEmpty()) {
                throw new DocScanException("manifest: neither \"critical_information\" nor \"detection\"");
            }
            JSONObject chunk = o.optJSONObject("critical_chunk");
            if (chunk != null) {
                m.chunkSize = chunk.optInt("size", 0);
                m.chunkOverlap = chunk.optInt("overlap", -1);
                if (m.chunkSize != 0 && (m.chunkSize < 200 || m.chunkSize > 1500
                        || m.chunkOverlap < 0 || m.chunkOverlap > m.chunkSize / 2)) {
                    throw new DocScanException("manifest: critical_chunk must be size 200..1500, overlap 0..size/2");
                }
            }
            JSONObject files = o.optJSONObject("files");
            if (files != null) {
                for (Iterator<String> it = files.keys(); it.hasNext(); ) {
                    String k = it.next();
                    m.sha256.put(checkPath(k, "files"), files.getString(k));
                }
            }
            return m;
        } catch (JSONException e) {
            throw new DocScanException("bad manifest.json: " + e.getMessage(), e);
        }
    }

    private static void paths(Object v, List<String> out, String field) throws DocScanException, JSONException {
        if (v == null || JSONObject.NULL.equals(v)) return;
        if (v instanceof String) {
            out.add(checkPath((String) v, field));
        } else if (v instanceof JSONArray) {
            JSONArray a = (JSONArray) v;
            for (int i = 0; i < a.length(); i++) out.add(checkPath(a.getString(i), field));
        } else {
            throw new DocScanException("manifest: \"" + field + "\" must be a path or a list of paths");
        }
    }

    private static String checkPath(String p, String field) throws DocScanException {
        String n = p.replace('\\', '/');
        if (n.isEmpty() || n.startsWith("/") || n.contains("../") || n.equals("..") || n.contains(":")) {
            throw new DocScanException("manifest: bad path in \"" + field + "\": " + p);
        }
        return n;
    }

    // ------------------------------------------------------------ helpers

    /** Several rule files compile as one set through a generated index of includes. */
    private static void compile(File dir, List<String> files, File out, String what) throws DocScanException {
        File index;
        if (files.size() == 1) {
            index = new File(dir, files.get(0));
        } else {
            index = new File(dir, "_index_" + what + ".yar");
            StringBuilder sb = new StringBuilder();
            for (String f : files) sb.append("include \"").append(f.replace("\"", "\\\"")).append("\"\n");
            try {
                write(index, sb.toString());
            } catch (IOException e) {
                throw new DocScanException(e.getMessage(), e);
            }
        }
        long h;
        try {
            h = NativeYara.compile(index.getPath());
        } catch (DocScanException e) {
            throw new DocScanException(what + ": " + e.getMessage().replace(dir.getPath() + "/", ""), e);
        }
        try {
            if (!NativeYara.save(h, out.getPath())) throw new DocScanException(what + ": cannot save the compiled rules");
        } finally {
            NativeYara.destroy(h);
        }
    }

    private static Manifest peekManifest(File zip) {
        try (ZipInputStream z = new ZipInputStream(new FileInputStream(zip))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (MANIFEST.equals(e.getName())) {
                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    copy(z, bo, 1024 * 1024);
                    return parseManifest(bo.toString("UTF-8"));
                }
            }
        } catch (IOException | DocScanException ignored) {
            // full install will report it
        }
        return null;
    }

    static String sha256(File f) throws DocScanException {
        try (InputStream in = new FileInputStream(f)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format(Locale.ROOT, "%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new DocScanException("sha256: " + e.getMessage(), e);
        }
    }

    private static long copy(InputStream in, OutputStream out, long max) throws IOException {
        byte[] buf = new byte[64 * 1024];
        long n = 0;
        int r;
        while ((r = in.read(buf)) > 0) {
            n += r;
            if (n > max) throw new IOException("the archive is too large");
            out.write(buf, 0, r);
        }
        return n;
    }

    static String read(File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            copy(in, bo, 16L * 1024 * 1024);
            return bo.toString("UTF-8");
        }
    }

    private static void write(File f, String s) throws IOException {
        try (OutputStream o = new FileOutputStream(f)) {
            o.write(s.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** For the UI: the rule file names of the critical set. */
    public static List<String> criticalNames(Info i) {
        if (i == null) return Collections.emptyList();
        List<String> out = new ArrayList<>();
        for (String p : i.manifest.critical) out.add(p.substring(p.lastIndexOf('/') + 1));
        return out;
    }
}
