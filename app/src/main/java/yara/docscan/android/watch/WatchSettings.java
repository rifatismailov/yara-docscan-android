package yara.docscan.android.watch;

import android.content.Context;
import android.content.SharedPreferences;

/** User settings of the watcher (the parameters of docscan-watcher.ps1 that make sense on a phone). */
public final class WatchSettings {
    private static final String PREFS = "watcher";

    private final SharedPreferences p;

    public WatchSettings(Context ctx) {
        p = ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /** The user turned protection on (the service is kept running / restarted). */
    public boolean enabled() {
        return p.getBoolean("enabled", false);
    }

    public void setEnabled(boolean v) {
        p.edit().putBoolean("enabled", v).apply();
    }

    /** Cure documents per meta.disarm (default, like the PC watcher); false = -NoDisarm / detect only. */
    public boolean cure() {
        return p.getBoolean("cure", true);
    }

    public void setCure(boolean v) {
        p.edit().putBoolean("cure", v).apply();
    }

    /** A HIGH package file goes to quarantine (needs cure() too). */
    public boolean quarantineApk() {
        return p.getBoolean("quarantine_apk", true);
    }

    public void setQuarantineApk(boolean v) {
        p.edit().putBoolean("quarantine_apk", v).apply();
    }

    /** -MaxSizeMB: larger files are skipped (logged). */
    public int maxSizeMb() {
        return p.getInt("max_size_mb", 100);
    }

    public long lastCatchUp() {
        return p.getLong("last_catch_up", 0);
    }

    public void setLastCatchUp(long t) {
        p.edit().putLong("last_catch_up", t).apply();
    }
}
