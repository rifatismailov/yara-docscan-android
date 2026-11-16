package yara.docscan.android;

import android.content.Context;
import android.content.res.AssetManager;

import androidx.test.platform.app.InstrumentationRegistry;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The 42 inert test documents of yara-docscan (test-samples/generated) and the reference results of
 * the PC version (docscan-project/ci/expected-verdicts.tsv: file, verdict, disarm, verdict after disarm).
 */
final class Samples {
    static final class Row {
        final String name, verdict, disarm, after;

        Row(String[] c) {
            name = c[0];
            verdict = c[1];
            disarm = c[2];
            after = c[3];
        }
    }

    private Samples() {}

    static Context app() {
        return InstrumentationRegistry.getInstrumentation().getTargetContext();
    }

    static List<Row> expected() throws IOException {
        AssetManager am = InstrumentationRegistry.getInstrumentation().getContext().getAssets();
        List<Row> rows = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                am.open("expected-verdicts.tsv"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;
                rows.add(new Row(line.split("\t")));
            }
        }
        return rows;
    }

    /** Installs a rules set with the given critical_information rule (an asset of the test APK). */
    static void installCriticalBundle(String asset) throws Exception {
        AssetManager am = InstrumentationRegistry.getInstrumentation().getContext().getAssets();
        java.io.ByteArrayOutputStream rule = new java.io.ByteArrayOutputStream();
        try (InputStream in = am.open(asset)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) rule.write(buf, 0, n);
        }
        String name = asset.substring(asset.lastIndexOf('/') + 1);
        java.io.ByteArrayOutputStream zip = new java.io.ByteArrayOutputStream();
        try (java.util.zip.ZipOutputStream z = new java.util.zip.ZipOutputStream(zip)) {
            z.putNextEntry(new java.util.zip.ZipEntry("manifest.json"));
            z.write(("{\"bundle\":\"docscan-rules\",\"version\":\"test-" + name + "\","
                    + "\"critical_information\":\"critical/" + name + "\"}").getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new java.util.zip.ZipEntry("critical/" + name));
            z.write(rule.toByteArray());
            z.closeEntry();
        }
        yara.docscan.android.scan.RulesBundle.install(app(), new java.io.ByteArrayInputStream(zip.toByteArray()),
                "test:" + name, null);
    }

    /** Copies an asset of the test APK to a file. */
    static File copyAsset(String asset, File f) throws IOException {
        AssetManager am = InstrumentationRegistry.getInstrumentation().getContext().getAssets();
        File parent = f.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) throw new IOException("mkdir " + parent);
        try (InputStream in = am.open(asset); OutputStream out = new FileOutputStream(f)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
        return f;
    }

    /** A fresh copy of the sample in dir. */
    static File copy(String name, File dir) throws IOException {
        AssetManager am = InstrumentationRegistry.getInstrumentation().getContext().getAssets();
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("mkdir " + dir);
        File f = new File(dir, name);
        try (InputStream in = am.open("samples/" + name); OutputStream out = new FileOutputStream(f)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
        return f;
    }
}
