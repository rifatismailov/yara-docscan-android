package yara.docscan.android.device;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

import yara.docscan.android.watch.FileIndex;
import yara.docscan.android.watch.Notifier;
import yara.docscan.android.watch.ResultLog;

/**
 * Watches the settings malware needs: the moment a third-party app gets an accessibility service,
 * notification access or device admin, the user is alerted and a record goes to the results log.
 * Settings.Secure changes arrive at once (ContentObserver); device admins are compared on every check.
 */
public final class DeviceMonitor extends ContentObserver {
    private static final String PREFS = "device_monitor";

    private final Context ctx;
    private final HandlerThread thread;
    private final Handler handler;
    private final String host;
    private final Runnable check = this::checkNow;

    public static DeviceMonitor start(Context ctx, String host) {
        HandlerThread t = new HandlerThread("docscan-device");
        t.start();
        DeviceMonitor m = new DeviceMonitor(ctx, t, host);
        android.content.ContentResolver cr = ctx.getContentResolver();
        cr.registerContentObserver(Settings.Secure.getUriFor(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES), false, m);
        cr.registerContentObserver(Settings.Secure.getUriFor("enabled_notification_listeners"), false, m);
        cr.registerContentObserver(Settings.Global.getUriFor(Settings.Global.ADB_ENABLED), false, m);
        m.handler.post(m.check);   // baseline / changes while we were not running
        return m;
    }

    private DeviceMonitor(Context ctx, HandlerThread t, String host) {
        super(new Handler(t.getLooper()));
        this.ctx = ctx.getApplicationContext();
        this.thread = t;
        this.handler = new Handler(t.getLooper());
        this.host = host;
    }

    public void stop() {
        ctx.getContentResolver().unregisterContentObserver(this);
        thread.quitSafely();
    }

    @Override
    public void onChange(boolean selfChange, Uri uri) {
        handler.removeCallbacks(check);
        handler.postDelayed(check, 500);
    }

    /** Also called by the periodic sweep (device admins have no change notification). */
    public void checkNow() {
        SharedPreferences p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        boolean first = !p.getBoolean("baseline", false);
        diff(p, first, "accessibility", DevicePosture.enabledAccessibility(ctx), "HIGH",
                "Увімкнено спеціальні можливості",
                "отримав доступ до спеціальних можливостей: бачить екран і може натискати за вас. "
                        + "Якщо ви цього не робили — це типова поведінка банківського трояна, вимкніть у Налаштуваннях → Спеціальні можливості");
        diff(p, first, "notification_listeners", DevicePosture.enabledNotificationListeners(ctx), "MEDIUM",
                "Доступ до сповіщень",
                "отримав доступ до всіх сповіщень, зокрема кодів підтвердження з SMS");
        diff(p, first, "device_admins", DevicePosture.activeAdmins(ctx), "HIGH",
                "Новий адміністратор пристрою",
                "отримав права адміністратора пристрою: може блокувати екран і заважати видаленню");
        boolean adb = Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1;
        boolean adbWas = p.getBoolean("adb", adb);
        if (!first && adb && !adbWas) {
            report("adb", "MEDIUM", "Увімкнено налагодження USB",
                    "Налагодження USB увімкнено: через кабель можна встановлювати застосунки й читати дані", new TreeSet<>());
        }
        p.edit().putBoolean("adb", adb).putBoolean("baseline", true).apply();
    }

    private void diff(SharedPreferences p, boolean first, String key, Set<String> now, String verdict,
                      String title, String what) {
        Set<String> before = new HashSet<>(p.getStringSet(key, new HashSet<>()));
        Set<String> added = new TreeSet<>(now);
        added.removeAll(before);
        p.edit().putStringSet(key, new HashSet<>(now)).apply();
        if (first || added.isEmpty()) return;
        report(key, verdict, title, DevicePosture.labels(ctx, added) + " " + what, added);
    }

    private void report(String check, String verdict, String title, String text, Set<String> packages) {
        Notifier.device(ctx, title, text);
        JSONObject rec = new JSONObject();
        try {
            rec.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.ROOT).format(new Date()));
            rec.put("source", "docscan");
            rec.put("platform", "android");
            rec.put("host", host);
            rec.put("event", "DeviceChange");
            rec.put("category", "device");
            rec.put("device", new JSONObject().put("check", check).put("packages", new JSONArray(packages)));
            rec.put("verdict", verdict);
            rec.put("summary", title + ": " + text);
        } catch (JSONException ignored) {
            // constant keys
        }
        ResultLog.get(ctx).append("device:" + check + ":" + packages, rec);
        FileIndex.get(ctx).addEvent("device", check, verdict, title + ": " + text, rec.toString());
    }
}
