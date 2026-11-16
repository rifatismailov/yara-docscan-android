package yara.docscan.android.watch;

import android.os.Build;
import android.os.FileObserver;
import android.util.Log;

import java.io.File;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * inotify over a whole tree: FileObserver watches one directory, so there is one per directory, and a
 * new directory gets its own as soon as it appears. Excluded paths (WatchFilter) are not watched.
 */
public final class RecursiveObserver {
    private static final String TAG = "RecursiveObserver";
    private static final int MASK = FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO | FileObserver.CREATE
            | FileObserver.DELETE_SELF | FileObserver.MOVE_SELF;
    /** inotify watches are limited per user (often 8192, shared with other apps). */
    static final int MAX_WATCHES = 6000;

    public interface Listener {
        /** A file was written / moved in. event: Created / Changed / Renamed. */
        void onFile(File f, String event);

        /** A directory appeared (created or moved in): its files were never seen. */
        void onNewDirectory(File dir);
    }

    private final File root;
    private final String rootPath;
    private final Listener listener;
    private final Map<String, FileObserver> watches = new HashMap<>();   // strong refs: a GC'd observer stops
    private boolean full;

    public RecursiveObserver(File root, Listener listener) {
        this.root = root;
        this.rootPath = root.getAbsolutePath();
        this.listener = listener;
    }

    public synchronized int count() {
        return watches.size();
    }

    /** The tree did not fit into MAX_WATCHES: the periodic sweep covers the rest. */
    public synchronized boolean isFull() {
        return full;
    }

    public void start() {
        addTree(root);
        Log.i(TAG, "watching " + count() + " directories under " + rootPath + (isFull() ? " (limit reached)" : ""));
    }

    public synchronized void stop() {
        for (FileObserver o : watches.values()) o.stopWatching();
        watches.clear();
    }

    /** Every directory under dir that is watched (for the initial sweep). */
    public synchronized List<File> directories() {
        List<File> out = new ArrayList<>();
        for (String p : watches.keySet()) out.add(new File(p));
        return out;
    }

    String relative(File f) {
        String p = f.getAbsolutePath();
        if (p.equals(rootPath)) return "";
        return p.startsWith(rootPath + "/") ? p.substring(rootPath.length() + 1) : p;
    }

    private void addTree(File top) {
        ArrayDeque<File> q = new ArrayDeque<>();
        q.add(top);
        while (!q.isEmpty()) {
            File d = q.poll();
            if (!addOne(d)) continue;
            File[] kids = d.listFiles();
            if (kids == null) continue;
            for (File k : kids) if (k.isDirectory()) q.add(k);
        }
    }

    private synchronized boolean addOne(File dir) {
        String path = dir.getAbsolutePath();
        if (watches.containsKey(path)) return true;
        if (!path.equals(rootPath) && WatchFilter.isExcluded(relative(dir))) return false;
        if (watches.size() >= MAX_WATCHES) {
            full = true;
            return false;
        }
        FileObserver o = create(dir);
        o.startWatching();
        watches.put(path, o);
        return true;
    }

    private synchronized void remove(File dir) {
        String prefix = dir.getAbsolutePath();
        List<String> gone = new ArrayList<>();
        for (String p : watches.keySet()) if (p.equals(prefix) || p.startsWith(prefix + "/")) gone.add(p);
        for (String p : gone) {
            FileObserver o = watches.remove(p);
            if (o != null) o.stopWatching();
        }
    }

    @SuppressWarnings("deprecation")
    private FileObserver create(File dir) {
        if (Build.VERSION.SDK_INT >= 29) {
            return new FileObserver(dir, MASK) {
                @Override
                public void onEvent(int event, String name) {
                    handle(dir, event, name);
                }
            };
        }
        return new FileObserver(dir.getPath(), MASK) {
            @Override
            public void onEvent(int event, String name) {
                handle(dir, event, name);
            }
        };
    }

    private void handle(File dir, int event, String name) {
        int e = event & FileObserver.ALL_EVENTS;
        if ((e & (FileObserver.DELETE_SELF | FileObserver.MOVE_SELF)) != 0) {
            remove(dir);
            return;
        }
        if (name == null) return;
        File f = new File(dir, name);
        if (WatchFilter.isExcluded(relative(f))) return;
        if ((e & (FileObserver.CREATE | FileObserver.MOVED_TO)) != 0 && f.isDirectory()) {
            addTree(f);
            listener.onNewDirectory(f);
            return;
        }
        if ((e & FileObserver.CLOSE_WRITE) != 0) listener.onFile(f, "Changed");
        else if ((e & FileObserver.MOVED_TO) != 0) listener.onFile(f, "Renamed");
        // CREATE of a file: wait for its CLOSE_WRITE
    }
}
