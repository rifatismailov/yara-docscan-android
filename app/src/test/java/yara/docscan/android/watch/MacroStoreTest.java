package yara.docscan.android.watch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

/** Save-Macro / Sync-Macros of docscan-watcher.ps1. */
public class MacroStoreTest {
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File write(String name, byte[] b) throws Exception {
        File f = tmp.newFile(name);
        try (FileOutputStream o = new FileOutputStream(f)) {
            o.write(b);
        }
        return f;
    }

    @Test
    public void utf8IsKeptAnsiIsDecodedAs1251() {
        assertEquals("Sub AutoOpen()", MacroStore.decode("Sub AutoOpen()".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("' привіт", MacroStore.decode("' привіт".getBytes(StandardCharsets.UTF_8)));
        assertEquals("' привет", MacroStore.decode("' привет".getBytes(Charset.forName("windows-1251"))));
    }

    @Test
    public void savesOncePerContentWithHeader() throws Exception {
        MacroStore s = new MacroStore(tmp.newFolder("macros"));
        File code = write("vba.tmp", "Sub AutoOpen()\r\nShell \"calc\"\r\nEnd Sub".getBytes(StandardCharsets.US_ASCII));
        File f = s.save("abc123", code, "phone", "/sdcard/Download/a.docm", Arrays.asList("MACRO_PRESENT", "MACRO_AUTOEXEC"));
        assertEquals("abc123.vba.txt", f.getName());
        String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        assertTrue(text.startsWith("' DocScan macro\r\n' host: phone\r\n' file: /sdcard/Download/a.docm\r\n' sha256: abc123\r\n' findings: MACRO_PRESENT, MACRO_AUTOEXEC\r\n' saved: "));
        assertTrue(text.endsWith("Shell \"calc\"\r\nEnd Sub"));
        long size = f.length();
        File again = s.save("abc123", write("vba2.tmp", "other".getBytes(StandardCharsets.US_ASCII)), "phone", "x", Arrays.asList());
        assertEquals(size, again.length());   // the same document content is stored once
        assertNull(s.save("e", write("empty.tmp", new byte[0]), "phone", "x", Arrays.asList()));
        assertEquals(1, s.count());
    }

    @Test
    public void retentionDropsOldFiles() throws Exception {
        File dir = tmp.newFolder("macros");
        MacroStore s = new MacroStore(dir);
        File code = write("vba.tmp", "Sub X()\r\nEnd Sub".getBytes(StandardCharsets.US_ASCII));
        File old = s.save("old", code, "h", "p", Arrays.asList());
        File fresh = s.save("new", code, "h", "p", Arrays.asList());
        assertTrue(old.setLastModified(System.currentTimeMillis() - (MacroStore.KEEP_DAYS + 1) * 24L * 3600 * 1000));
        s.sync("");
        assertFalse(old.exists());
        assertTrue(fresh.exists());
    }
}
