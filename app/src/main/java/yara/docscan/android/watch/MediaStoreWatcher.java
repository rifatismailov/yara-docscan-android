package yara.docscan.android.watch;

import android.content.Context;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.provider.MediaStore;

import java.io.File;

/**
 * The second signal next to inotify: on Android 11+ part of the writes to shared storage go through
 * MediaProvider and may not reach FileObserver. On a MediaStore change, the files modified since the
 * last check are handed to the queue (which de-duplicates with the inotify events).
 */
public final class MediaStoreWatcher extends ContentObserver {
    private static final long DEBOUNCE_MS = 3_000;

    public interface Listener {
        void onFile(File f);
    }

    private final Context ctx;
    private final Listener listener;
    private final Handler handler;
    private final HandlerThread thread;
    private long lastCheckSec;
    private final Runnable check = this::check;

    public static MediaStoreWatcher start(Context ctx, Listener l) {
        HandlerThread t = new HandlerThread("docscan-mediastore");
        t.start();
        MediaStoreWatcher w = new MediaStoreWatcher(ctx, l, t);
        ctx.getContentResolver().registerContentObserver(MediaStore.Files.getContentUri("external"), true, w);
        return w;
    }

    private MediaStoreWatcher(Context ctx, Listener l, HandlerThread t) {
        super(new Handler(t.getLooper()));
        this.ctx = ctx.getApplicationContext();
        this.listener = l;
        this.thread = t;
        this.handler = new Handler(t.getLooper());
        this.lastCheckSec = System.currentTimeMillis() / 1000;
    }

    public void stop() {
        ctx.getContentResolver().unregisterContentObserver(this);
        thread.quitSafely();
    }

    @Override
    public void onChange(boolean selfChange, Uri uri) {
        handler.removeCallbacks(check);
        handler.postDelayed(check, DEBOUNCE_MS);
    }

    @SuppressWarnings("deprecation")   // DATA: readable with all-files access / legacy storage
    private void check() {
        long since = lastCheckSec - 2;
        lastCheckSec = System.currentTimeMillis() / 1000;
        String[] cols = {MediaStore.MediaColumns.DATA};
        try (Cursor c = ctx.getContentResolver().query(MediaStore.Files.getContentUri("external"), cols,
                MediaStore.MediaColumns.DATE_MODIFIED + ">=?", new String[] {String.valueOf(since)}, null)) {
            if (c == null) return;
            while (c.moveToNext()) {
                String p = c.getString(0);
                if (p == null || WatchFilter.category(p) == null) continue;
                File f = new File(p);
                if (f.isFile()) listener.onFile(f);
            }
        } catch (RuntimeException ignored) {
            // no storage permission yet
        }
    }
}
