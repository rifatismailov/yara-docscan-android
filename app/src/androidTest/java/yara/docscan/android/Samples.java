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
