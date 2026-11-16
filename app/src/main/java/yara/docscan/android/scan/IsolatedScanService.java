package yara.docscan.android.scan;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Sandboxed worker: runs in its own process under a random isolated uid with no permissions and no
 * access to any file (android:isolatedProcess="true"). Everything arrives as file descriptors.
 *
 * <p>A crash here (a parser bug hit by a hostile file) kills only this process; the broker sees a
 * DeadObjectException, reports the file as ERROR and rebinds.
 */
public class IsolatedScanService extends Service {
    private static final String TAG = "ScanWorker";
    private static final int YARA_TIMEOUT_SEC = 120;
    /** Hard limit for one call (the docscan module parses before YARA's timeout applies). */
    private static final int WATCHDOG_SEC = 180;

    private static final Pattern DEX_ENTRY = Pattern.compile("^classes\\d*\\.dex$");
    private static final long MAX_DEX_BYTES = 64L * 1024 * 1024;
    private static final long MAX_DEX_TOTAL = 160L * 1024 * 1024;
    private static final int MAX_DEX_FILES = 32;

    private static long rules;
    private static long criticalRules;
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor();

    private final IScanWorker.Stub binder = new IScanWorker.Stub() {
        @Override
        public synchronized String init(ParcelFileDescriptor rulesFd) {
            try (ParcelFileDescriptor pfd = rulesFd) {
                long h = NativeYara.loadFd(pfd.getFd());
                if (h == 0) return null;
                if (rules != 0) NativeYara.destroy(rules);
                rules = h;
                return NativeYara.version();
            } catch (IOException e) {
                return null;
            }
        }

        @Override
        public synchronized boolean initCritical(ParcelFileDescriptor rulesFd) {
            if (criticalRules != 0) {
                NativeYara.destroy(criticalRules);
                criticalRules = 0;
            }
            if (rulesFd == null) return true;
            try (ParcelFileDescriptor pfd = rulesFd) {
                criticalRules = NativeYara.loadFd(pfd.getFd());
                return criticalRules != 0;
            } catch (IOException e) {
                return false;
            }
        }

        @Override
        public synchronized Bundle scan(ParcelFileDescriptor file, String name, String dir,
                                        boolean planDisarm, ParcelFileDescriptor curedOut,
                                        ParcelFileDescriptor macroOut, ParcelFileDescriptor criticalOut) {
            Bundle out = new Bundle();
            ScheduledFuture<?> guard = watchdog.schedule(() -> {
                Log.e(TAG, "scan of " + name + " exceeded " + WATCHDOG_SEC + " s - killing the worker");
                Process.killProcess(Process.myPid());
            }, WATCHDOG_SEC, TimeUnit.SECONDS);
            try {
                if (rules == 0) {
                    out.putString("error", "worker has no rules");
                    return out;
                }
                byte[] json = NativeYara.scanFd(rules, file.getFd(), name, dir, YARA_TIMEOUT_SEC,
                        planDisarm, curedOut != null ? curedOut.getFd() : -1,
                        macroOut != null ? macroOut.getFd() : -1);
                out.putByteArray("json", json);
                // pass 3 on the original, before any cure (the broker cures after this call)
                if (criticalOut != null && criticalRules != 0) {
                    String path = dir.isEmpty() ? name : dir + "/" + name;
                    out.putByteArray("critical", NativeYara.critical(criticalRules, file.getFd(), name, path,
                            0, -1, YARA_TIMEOUT_SEC, criticalOut.getFd()));
                }
                if (looksLikeApk(json)) {
                    byte[] dex = scanDex(file, name);
                    if (dex != null) out.putByteArray("dex", dex);
                }
            } catch (Throwable t) {
                out.putString("error", String.valueOf(t.getMessage()));
            } finally {
                guard.cancel(false);
                closeQuietly(file);
                closeQuietly(curedOut);
                closeQuietly(macroOut);
                closeQuietly(criticalOut);
            }
            return out;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    /** A ZIP with AndroidManifest.xml and classes.dex at its root (archive_entries of the docscan JSON). */
    static boolean looksLikeApk(byte[] json) {
        try {
            JSONObject o = new JSONObject(new String(json, StandardCharsets.UTF_8));
            if (!"zip".equals(o.optString("ftype"))) return false;
            JSONArray e = o.optJSONArray("archive_entries");
            if (e == null) return false;
            boolean manifest = false, dex = false;
            for (int i = 0; i < e.length(); i++) {
                String n = e.optString(i);
                if ("AndroidManifest.xml".equals(n)) manifest = true;
                if ("classes.dex".equals(n)) dex = true;
            }
            return manifest && dex;
        } catch (Exception ex) {
            return false;
        }
    }

    /** Vendor rules over every classes*.dex of the APK -> {"dex":[{"part":..,"rules":[..]}],"descriptions":[..]}. */
    private static byte[] scanDex(ParcelFileDescriptor file, String name) throws Exception {
        JSONArray parts = new JSONArray();
        JSONArray descriptions = new JSONArray();
        FileInputStream fin = new FileInputStream(file.getFileDescriptor());
        fin.getChannel().position(0);
        long total = 0;
        int files = 0;
        try (ZipInputStream zin = new ZipInputStream(fin)) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null && files < MAX_DEX_FILES && total < MAX_DEX_TOTAL) {
                if (e.isDirectory() || !DEX_ENTRY.matcher(e.getName()).matches()) continue;
                byte[] dex = readLimited(zin, MAX_DEX_BYTES);
                if (dex == null) continue;  // larger than the limit: skipped
                files++;
                total += dex.length;
                JSONObject r = new JSONObject(new String(
                        NativeYara.scanMem(rules, dex, dex.length, e.getName(), YARA_TIMEOUT_SEC),
                        StandardCharsets.UTF_8));
                JSONArray matched = r.optJSONArray("rules");
                if (matched != null && matched.length() > 0) {
                    parts.put(new JSONObject().put("part", e.getName()).put("rules", matched));
                }
                JSONArray d = r.optJSONArray("descriptions");
                for (int i = 0; d != null && i < d.length(); i++) descriptions.put(d.get(i));
            }
        }
        return new JSONObject().put("dex", parts).put("dex_files", files).put("descriptions", descriptions)
                .toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] readLimited(InputStream in, long max) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[64 * 1024];
        long n = 0;
        int r;
        while ((r = in.read(buf)) > 0) {
            n += r;
            if (n > max) return null;
            bo.write(buf, 0, r);
        }
        return bo.toByteArray();
    }

    private static void closeQuietly(ParcelFileDescriptor p) {
        if (p == null) return;
        try {
            p.close();
        } catch (IOException ignored) {
        }
    }
}
