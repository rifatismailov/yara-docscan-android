package yara.docscan.android.watch;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

/**
 * What has been scanned: files (path, size, mtime -> skip unchanged files in the catch-up sweep),
 * installed apps (lastUpdateTime) and the event journal shown in the app.
 */
public final class FileIndex extends SQLiteOpenHelper {
    private static final int VERSION = 1;
    private static final int MAX_EVENTS = 3000;
    private static volatile FileIndex instance;

    public static final class Event {
        public final long id, time;
        public final String kind;      // file / app / device
        public final String subject;   // path, package or check name
        public final String verdict, summary, json;

        Event(Cursor c) {
            id = c.getLong(0);
            time = c.getLong(1);
            kind = c.getString(2);
            subject = c.getString(3);
            verdict = c.getString(4);
            summary = c.getString(5);
            json = c.getString(6);
        }
    }

    public static FileIndex get(Context ctx) {
        FileIndex i = instance;
        if (i == null) {
            synchronized (FileIndex.class) {
                i = instance;
                if (i == null) instance = i = new FileIndex(ctx.getApplicationContext());
            }
        }
        return i;
    }

    private FileIndex(Context ctx) {
        super(ctx, "docscan.db", null, VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE files (path TEXT PRIMARY KEY, size INTEGER, mtime INTEGER, sha256 TEXT,"
                + " verdict TEXT, ts INTEGER)");
        db.execSQL("CREATE TABLE apps (pkg TEXT PRIMARY KEY, update_time INTEGER, verdict TEXT, ts INTEGER)");
        db.execSQL("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT,"
                + " subject TEXT, verdict TEXT, summary TEXT, json TEXT)");
        db.execSQL("CREATE INDEX events_ts ON events(ts)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // first version
    }

    /** The file was scanned in this state already. */
    public boolean isUnchanged(String path, long size, long mtime) {
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT 1 FROM files WHERE path=? AND size=? AND mtime=?",
                new String[] {path, String.valueOf(size), String.valueOf(mtime)})) {
            return c.moveToFirst();
        }
    }

    public void putFile(String path, long size, long mtime, String sha256, String verdict) {
        ContentValues v = new ContentValues();
        v.put("path", path);
        v.put("size", size);
        v.put("mtime", mtime);
        v.put("sha256", sha256);
        v.put("verdict", verdict);
        v.put("ts", System.currentTimeMillis());
        getWritableDatabase().insertWithOnConflict("files", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public void forgetFile(String path) {
        getWritableDatabase().delete("files", "path=?", new String[] {path});
    }

    public long appUpdateTime(String pkg) {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT update_time FROM apps WHERE pkg=?", new String[] {pkg})) {
            return c.moveToFirst() ? c.getLong(0) : -1;
        }
    }

    public void putApp(String pkg, long updateTime, String verdict) {
        ContentValues v = new ContentValues();
        v.put("pkg", pkg);
        v.put("update_time", updateTime);
        v.put("verdict", verdict);
        v.put("ts", System.currentTimeMillis());
        getWritableDatabase().insertWithOnConflict("apps", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public void addEvent(String kind, String subject, String verdict, String summary, String json) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues v = new ContentValues();
        v.put("ts", System.currentTimeMillis());
        v.put("kind", kind);
        v.put("subject", subject);
        v.put("verdict", verdict);
        v.put("summary", summary);
        v.put("json", json);
        db.insert("events", null, v);
        db.execSQL("DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)",
                new Object[] {MAX_EVENTS});
    }

    /** Newest first; onlyThreats = MEDIUM / HIGH / ERROR. */
    public List<Event> events(int limit, boolean onlyThreats) {
        List<Event> out = new ArrayList<>();
        String where = onlyThreats ? " WHERE verdict IN ('HIGH','MEDIUM','ERROR')" : "";
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT id, ts, kind, subject, verdict, summary, json FROM events" + where
                        + " ORDER BY id DESC LIMIT " + limit, null)) {
            while (c.moveToNext()) out.add(new Event(c));
        }
        return out;
    }

    public int count(String table) {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM " + table, null)) {
            return c.moveToFirst() ? c.getInt(0) : 0;
        }
    }

    public int countThreats() {
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT COUNT(*) FROM events WHERE verdict IN ('HIGH','MEDIUM')", null)) {
            return c.moveToFirst() ? c.getInt(0) : 0;
        }
    }
}
