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

    /** -QuarantineGeneral: general files (exe / scripts / archives) matching vendor rules -> quarantine. */
    public boolean quarantineGeneral() {
        return p.getBoolean("quarantine_general", false);
    }

    public void setQuarantineGeneral(boolean v) {
        p.edit().putBoolean("quarantine_general", v).apply();
    }

    /** -MacroUpload: the collector the macro store is also sent to ("" = keep it local). */
    public String macroUploadUrl() {
        return p.getString("macro_upload", "");
    }

    public void setMacroUploadUrl(String v) {
        p.edit().putString("macro_upload", v == null ? "" : v.trim()).apply();
    }

    public long lastMacroSync() {
        return p.getLong("last_macro_sync", 0);
    }

    public void setLastMacroSync(long t) {
        p.edit().putLong("last_macro_sync", t).apply();
    }

    /** Pass 3 (critical information) on: needs critical_information rules in the installed rules set. */
    public boolean criticalEnabled() {
        return p.getBoolean("critical_enabled", false);
    }

    public void setCriticalEnabled(boolean v) {
        p.edit().putBoolean("critical_enabled", v).apply();
    }

    /** Where rules updates come from (a ZIP with manifest.json); "" = updates only from a file. */
    public String rulesUrl() {
        return p.getString("rules_url", "");
    }

    public void setRulesUrl(String v) {
        p.edit().putString("rules_url", v == null ? "" : v.trim()).apply();
    }

    public long lastRulesCheck() {
        return p.getLong("last_rules_check", 0);
    }

    public void setLastRulesCheck(long t) {
        p.edit().putLong("last_rules_check", t).apply();
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
