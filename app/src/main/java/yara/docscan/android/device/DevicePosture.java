package yara.docscan.android.device;

import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import java.io.File;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/** Security posture of the device - what an app without root can check. */
public final class DevicePosture {
    public static final String OK = "ok", WARN = "warn", BAD = "bad";

    public static final class Check {
        public final String id, title, status, detail;

        Check(String id, String title, String status, String detail) {
            this.id = id;
            this.title = title;
            this.status = status;
            this.detail = detail;
        }
    }

    private DevicePosture() {}

    public static List<Check> run(Context ctx) {
        List<Check> out = new ArrayList<>();
        out.add(screenLock(ctx));
        out.add(patchLevel());
        out.add(encryption(ctx));
        out.add(accessibility(ctx));
        out.add(notificationListeners(ctx));
        out.add(deviceAdmins(ctx));
        out.add(unknownSources(ctx));
        out.add(adb(ctx));
        out.add(root());
        return out;
    }

    /** Worst status of the list. */
    public static String worst(List<Check> checks) {
        String w = OK;
        for (Check c : checks) {
            if (BAD.equals(c.status)) return BAD;
            if (WARN.equals(c.status)) w = WARN;
        }
        return w;
    }

    static Check screenLock(Context ctx) {
        KeyguardManager km = ctx.getSystemService(KeyguardManager.class);
        boolean secure = km != null && (Build.VERSION.SDK_INT >= 23 ? km.isDeviceSecure() : km.isKeyguardSecure());
        return new Check("screen_lock", "Блокування екрана", secure ? OK : BAD,
                secure ? "PIN, пароль або графічний ключ встановлено"
                        : "Немає блокування екрана: будь-хто з телефоном у руках має доступ до всього");
    }

    static Check patchLevel() {
        String patch = Build.VERSION.SDK_INT >= 23 ? Build.VERSION.SECURITY_PATCH : "";
        long months = -1;
        try {
            Date d = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).parse(patch);
            if (d != null) months = (System.currentTimeMillis() - d.getTime()) / (30L * 24 * 3600 * 1000);
        } catch (ParseException ignored) {
            // unknown format
        }
        String status = months < 0 ? WARN : months > 12 ? BAD : months > 3 ? WARN : OK;
        String detail = "Android " + Build.VERSION.RELEASE + ", патч безпеки " + (patch.isEmpty() ? "невідомий" : patch)
                + (months > 12 ? " — понад рік без оновлень: відомі вразливості не закриті" : "");
        return new Check("patch", "Оновлення безпеки", status, detail);
    }

    static Check encryption(Context ctx) {
        DevicePolicyManager dpm = ctx.getSystemService(DevicePolicyManager.class);
        int s = dpm != null ? dpm.getStorageEncryptionStatus() : DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED;
        boolean on = s == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                || (Build.VERSION.SDK_INT >= 24 && s == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER)
                || s == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY;
        boolean defaultKey = s == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY;
        return new Check("encryption", "Шифрування сховища", on && !defaultKey ? OK : on ? WARN : BAD,
                on ? (defaultKey ? "Увімкнено, але без пароля блокування (ключ за замовчуванням)" : "Увімкнено")
                        : "Сховище не зашифроване");
    }

    /** Third-party accessibility services that are turned on (the main tool of Android banking trojans). */
    public static Set<String> enabledAccessibility(Context ctx) {
        return thirdParty(ctx, Settings.Secure.getString(ctx.getContentResolver(),
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES));
    }

    public static Set<String> enabledNotificationListeners(Context ctx) {
        return thirdParty(ctx, Settings.Secure.getString(ctx.getContentResolver(), "enabled_notification_listeners"));
    }

    public static Set<String> activeAdmins(Context ctx) {
        DevicePolicyManager dpm = ctx.getSystemService(DevicePolicyManager.class);
        List<ComponentName> admins = dpm != null ? dpm.getActiveAdmins() : null;
        StringBuilder sb = new StringBuilder();
        if (admins != null) for (ComponentName c : admins) sb.append(c.flattenToString()).append(':');
        return thirdParty(ctx, sb.toString());
    }

    static Check accessibility(Context ctx) {
        Set<String> a = enabledAccessibility(ctx);
        return new Check("accessibility", "Спеціальні можливості", a.isEmpty() ? OK : WARN,
                a.isEmpty() ? "Сторонні служби не ввімкнені"
                        : "Увімкнено для: " + labels(ctx, a) + ". Такі служби бачать екран і можуть натискати за вас — "
                        + "залиште лише ті, яким довіряєте");
    }

    static Check notificationListeners(Context ctx) {
        Set<String> a = enabledNotificationListeners(ctx);
        return new Check("notification_listeners", "Доступ до сповіщень", a.isEmpty() ? OK : WARN,
                a.isEmpty() ? "Сторонні застосунки не читають сповіщення"
                        : "Читають сповіщення (зокрема коди з SMS): " + labels(ctx, a));
    }

    static Check deviceAdmins(Context ctx) {
        Set<String> a = activeAdmins(ctx);
        return new Check("device_admins", "Адміністратори пристрою", a.isEmpty() ? OK : WARN,
                a.isEmpty() ? "Сторонніх адміністраторів немає" : "Мають права адміністратора: " + labels(ctx, a));
    }

    @SuppressWarnings("deprecation")
    static Check unknownSources(Context ctx) {
        if (Build.VERSION.SDK_INT < 26) {
            int v = Settings.Secure.getInt(ctx.getContentResolver(), Settings.Secure.INSTALL_NON_MARKET_APPS, 0);
            return new Check("unknown_sources", "Невідомі джерела", v == 1 ? WARN : OK,
                    v == 1 ? "Дозволено встановлювати застосунки з файлів — шкідливий APK встановиться без перешкод"
                            : "Встановлення з файлів заборонено");
        }
        // Android 8+: a per-app permission ("Install unknown apps")
        Set<String> allowed = new TreeSet<>();
        PackageManager pm = ctx.getPackageManager();
        AppOpsManager ops = ctx.getSystemService(AppOpsManager.class);
        for (PackageInfo pi : pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            ApplicationInfo ai = pi.applicationInfo;
            if (ai == null || isSystem(ai) || pi.requestedPermissions == null) continue;
            boolean requests = false;
            for (String p : pi.requestedPermissions) {
                if ("android.permission.REQUEST_INSTALL_PACKAGES".equals(p)) requests = true;
            }
            if (!requests) continue;
            try {
                @SuppressWarnings("deprecation")
                int mode = ops.checkOpNoThrow("android:request_install_packages", ai.uid, pi.packageName);
                if (mode == AppOpsManager.MODE_ALLOWED) allowed.add(pi.packageName);
            } catch (RuntimeException ignored) {
                // cannot read the op of another app on this ROM
            }
        }
        return new Check("unknown_sources", "Невідомі джерела", allowed.isEmpty() ? OK : WARN,
                allowed.isEmpty() ? "Жоден сторонній застосунок не може встановлювати APK"
                        : "Можуть встановлювати застосунки з файлів: " + labels(ctx, allowed));
    }

    static Check adb(Context ctx) {
        boolean adb = Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1;
        return new Check("adb", "Налагодження USB", adb ? WARN : OK,
                adb ? "Увімкнено: через кабель можна встановлювати застосунки й читати дані. Вимкніть, якщо не розробляєте"
                        : "Вимкнено");
    }

    static Check root() {
        String[] su = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su", "/vendor/bin/su",
                "/su/bin/su", "/data/local/xbin/su", "/data/local/bin/su", "/data/adb/magisk"};
        List<String> found = new ArrayList<>();
        for (String p : su) if (new File(p).exists()) found.add(p);
        boolean testKeys = Build.TAGS != null && Build.TAGS.contains("test-keys");
        boolean bad = !found.isEmpty() || testKeys;
        return new Check("root", "Root / модифікована прошивка", bad ? BAD : OK,
                bad ? "Ознаки: " + (testKeys ? "збірка test-keys " : "") + String.join(", ", found)
                        + " — захист Android можна обійти" : "Ознак root не знайдено");
    }

    // ------------------------------------------------------------------ helpers

    /** Packages from a ':'-separated component list that are not system apps. */
    static Set<String> thirdParty(Context ctx, String components) {
        Set<String> out = new TreeSet<>();
        if (components == null || components.isEmpty()) return out;
        PackageManager pm = ctx.getPackageManager();
        for (String c : components.split(":")) {
            ComponentName cn = ComponentName.unflattenFromString(c.trim());
            if (cn == null || cn.getPackageName().equals(ctx.getPackageName())) continue;
            try {
                if (!isSystem(pm.getApplicationInfo(cn.getPackageName(), 0))) out.add(cn.getPackageName());
            } catch (PackageManager.NameNotFoundException e) {
                out.add(cn.getPackageName());   // a component of an unknown package: report it
            }
        }
        return out;
    }

    static boolean isSystem(ApplicationInfo ai) {
        return (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
    }

    public static String labels(Context ctx, Set<String> pkgs) {
        PackageManager pm = ctx.getPackageManager();
        List<String> out = new ArrayList<>();
        for (String p : pkgs) {
            try {
                out.add(pm.getApplicationLabel(pm.getApplicationInfo(p, 0)) + " (" + p + ")");
            } catch (PackageManager.NameNotFoundException e) {
                out.add(p);
            }
        }
        Collections.sort(out);
        return String.join(", ", out);
    }
}
