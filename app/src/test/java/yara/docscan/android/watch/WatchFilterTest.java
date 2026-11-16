package yara.docscan.android.watch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class WatchFilterTest {
    @Test
    public void categories() {
        assertEquals("document", WatchFilter.category("Invoice.DOCM"));
        assertEquals("document", WatchFilter.category("a/b/report.pdf"));
        assertEquals("general", WatchFilter.category("setup.exe"));
        assertEquals("general", WatchFilter.category("photos.zip"));
        assertEquals("general", WatchFilter.category("game.xapk"));
        assertEquals("apk", WatchFilter.category("Download/bank-update.apk"));
        assertNull(WatchFilter.category("IMG_0001.jpg"));
        assertNull(WatchFilter.category(".profile"));
        assertNull(WatchFilter.category("noext"));
    }

    @Test
    public void archives() {
        assertTrue(WatchFilter.isArchiveExt("x.zip"));
        assertTrue(WatchFilter.isArchiveExt("x.apks"));
        assertFalse(WatchFilter.isArchiveExt("x.rar"));
        assertFalse(WatchFilter.isArchiveExt("x.apk"));
    }

    @Test
    public void exclusions() {
        assertTrue(WatchFilter.isExcluded("Android/data/com.x/files/a.pdf"));
        assertTrue(WatchFilter.isExcluded("Android/obb"));
        assertTrue(WatchFilter.isExcluded("DCIM/.thumbnails/1.pdf"));
        assertTrue(WatchFilter.isExcluded("Download/.pending-123-a.docx"));
        assertTrue(WatchFilter.isExcluded("Download/a.docx.docscan-tmp"));
        assertTrue(WatchFilter.isExcluded("Documents/~$report.docx"));
        assertFalse(WatchFilter.isExcluded("Android/media/org.telegram.messenger/Telegram/Telegram Documents/a.docm"));
        assertFalse(WatchFilter.isExcluded("Download/a.docx"));
        assertFalse(WatchFilter.isExcluded("Telegram/Telegram Documents/x.apk"));
    }
}
