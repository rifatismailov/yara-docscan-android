package yara.docscan.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import yara.docscan.android.scan.CriticalRules;
import yara.docscan.android.scan.DocScanner;
import yara.docscan.android.scan.ScanResult;
import yara.docscan.android.watch.MacroStore;

/** The macro store (VBA out of the sandboxed worker, upload) and pass 3 (critical information). */
@RunWith(AndroidJUnit4.class)
public class MacroAndCriticalTest {
    private static final String PHRASE = "Документ для службового користування. Не поширювати.";

    @After
    public void tearDown() {
        CriticalRules.remove(Samples.app());
    }

    @Test
    public void vbaIsExtractedStoredAndUploaded() throws Exception {
        File dir = new File(Samples.app().getCacheDir(), "macro-test");
        File doc = Samples.copy("macro_suspicious.docm", dir);
        File vba = new File(dir, "vba.tmp");
        DocScanner.Options o = new DocScanner.Options();
        o.macro = vba;
        ScanResult r = DocScanner.get(Samples.app()).scan(doc, o);
        assertTrue("vba_size " + r.vbaSize, r.vbaSize > 0);
        assertEquals(r.vbaSize, vba.length());
        String code = new String(Files.readAllBytes(vba.toPath()), StandardCharsets.ISO_8859_1);
        assertTrue(code, code.contains("AutoOpen") && code.toLowerCase().contains("powershell"));

        // a document without macros writes nothing
        File clean = Samples.copy("dde_auto.docx", dir);
        File none = new File(dir, "none.tmp");
        o.macro = none;
        assertEquals(0, DocScanner.get(Samples.app()).scan(clean, o).vbaSize);
        assertEquals(0, none.length());

        // the store + Send-Macro to a collector (a local HTTP server here)
        MacroStore store = new MacroStore(new File(dir, "store"));
        File stored = store.save("deadbeef", vba, "test-host", doc.getPath(), r.findings);
        assertNotNull(stored);
        AtomicReference<String> received = new AtomicReference<>();
        try (ServerSocket server = new ServerSocket(0)) {
            Thread t = new Thread(() -> received.set(serveOnePost(server)));
            t.start();
            assertTrue(store.send(stored, "http://127.0.0.1:" + server.getLocalPort()));
            t.join(5000);
        }
        assertNotNull(received.get());
        assertTrue(received.get(), received.get().startsWith("' DocScan macro\r\n' host: test-host\r\n"));
        assertTrue(store.isSent(stored));
    }

    @Test
    public void passThreeQueuesDocumentsWithTheCriticalPhrase() throws Exception {
        InputStream rules = InstrumentationRegistry.getInstrumentation().getContext().getAssets().open("crit-test.yar");
        CriticalRules.install(Samples.app(), rules, "crit-test.yar");
        DocScanner scanner = DocScanner.get(Samples.app());
        File dir = new File(Samples.app().getCacheDir(), "critical-test");
        dir.mkdirs();

        File txt = new File(dir, "note.txt");
        try (OutputStream out = new FileOutputStream(txt)) {
            out.write(("Звіт за квартал.\n" + PHRASE + "\nКінець.").getBytes(StandardCharsets.UTF_8));
        }
        JSONObject line = queued(scanner, txt, dir);
        assertEquals("note.txt", line.getJSONObject("document").optString("name", line.toString()));

        File docx = new File(dir, "order.docx");
        writeDocx(docx, PHRASE);
        queued(scanner, docx, dir);

        // no phrase -> nothing queued
        File other = new File(dir, "plain.txt");
        try (OutputStream out = new FileOutputStream(other)) {
            out.write("Звичайний текст без грифа.".getBytes(StandardCharsets.UTF_8));
        }
        DocScanner.Options o = new DocScanner.Options();
        o.critical = new File(dir, "line3.tmp");
        ScanResult r = scanner.scan(other, o);
        assertEquals("nomatch", r.critical.getString("status"));
        assertEquals(0, o.critical.length());
    }

    private static JSONObject queued(DocScanner scanner, File f, File dir) throws Exception {
        DocScanner.Options o = new DocScanner.Options();
        o.critical = new File(dir, f.getName() + ".line");
        ScanResult r = scanner.scan(f, o);
        assertNotNull("pass 3 did not run on " + f.getName(), r.critical);
        assertEquals(r.critical.toString(), "queued", r.critical.getString("status"));
        JSONArray rules = r.critical.getJSONArray("rules");
        assertEquals("crit_test_grif", rules.getString(0));
        String text = new String(Files.readAllBytes(o.critical.toPath()), StandardCharsets.UTF_8);
        assertTrue(text.endsWith("\n"));
        JSONObject line = new JSONObject(text.trim());
        assertTrue(line.toString(), line.toString().contains("службового користування"));
        return line;
    }

    /** A minimal valid .docx with one paragraph. */
    private static void writeDocx(File f, String text) throws Exception {
        try (ZipOutputStream z = new ZipOutputStream(new FileOutputStream(f))) {
            put(z, "[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                    + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
                    + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
                    + "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
            put(z, "_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
                    + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>");
            put(z, "word/document.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
                    + "<w:body><w:p><w:r><w:t>" + text + "</w:t></w:r></w:p></w:body></w:document>");
        }
    }

    private static void put(ZipOutputStream z, String name, String body) throws Exception {
        z.putNextEntry(new ZipEntry(name));
        z.write(body.getBytes(StandardCharsets.UTF_8));
        z.closeEntry();
    }

    /** Accepts one HTTP POST, answers 200, returns the body. */
    private static String serveOnePost(ServerSocket server) {
        try (Socket s = server.accept()) {
            InputStream in = s.getInputStream();
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            int b, state = 0;
            while (state < 4 && (b = in.read()) >= 0) {
                head.write(b);
                state = (b == '\r' || b == '\n') ? state + 1 : 0;
            }
            int len = 0;
            for (String h : head.toString("ISO-8859-1").split("\r\n")) {
                if (h.toLowerCase().startsWith("content-length:")) len = Integer.parseInt(h.substring(15).trim());
            }
            byte[] body = new byte[len];
            int off = 0, n;
            while (off < len && (n = in.read(body, off, len - off)) > 0) off += n;
            s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII));
            return new String(body, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }
}
