package yara.docscan.android.ui;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.provider.Settings;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.util.Locale;

/** The permissions the watcher needs and how to ask for each. */
public final class Permissions {
    public static final int REQ_STORAGE = 10;
    public static final int REQ_NOTIFICATIONS = 11;

    private Permissions() {}

    /** Can read (and cure) files in the shared storage. */
    public static boolean storage(Context ctx) {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        return granted(ctx, Manifest.permission.READ_EXTERNAL_STORAGE)
                && granted(ctx, Manifest.permission.WRITE_EXTERNAL_STORAGE);
    }

    public static void requestStorage(Activity a) {
        if (Build.VERSION.SDK_INT >= 30) {
            Intent i = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + a.getPackageName()));
            if (!start(a, i)) start(a, new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
        } else {
            ActivityCompat.requestPermissions(a, new String[] {
                    Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_STORAGE);
        }
    }

    public static boolean notifications(Context ctx) {
        return Build.VERSION.SDK_INT < 33 || granted(ctx, Manifest.permission.POST_NOTIFICATIONS);
    }

    public static void requestNotifications(Activity a) {
        if (Build.VERSION.SDK_INT >= 33) {
            ActivityCompat.requestPermissions(a, new String[] {Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFICATIONS);
        }
    }

    public static boolean battery(Context ctx) {
        PowerManager pm = ctx.getSystemService(PowerManager.class);
        return pm != null && pm.isIgnoringBatteryOptimizations(ctx.getPackageName());
    }

    @SuppressWarnings("BatteryLife")   // a security watcher, distributed outside Google Play (MDM / APK)
    public static void requestBattery(Activity a) {
        Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:" + a.getPackageName()));
        if (!start(a, i)) start(a, new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
    }

    /** Vendors whose firmware kills background apps unless the user allows autostart. */
    public static String aggressiveVendor() {
        String m = Build.MANUFACTURER.toLowerCase(Locale.ROOT);
        for (String v : new String[] {"meizu", "xiaomi", "redmi", "poco", "huawei", "honor", "oppo", "realme",
                "vivo", "oneplus", "asus", "letv", "samsung"}) {
            if (m.contains(v)) return Build.MANUFACTURER;
        }
        return null;
    }

    /** The vendor's autostart / background screen when known, otherwise the app details. */
    public static void openAutostart(Activity a) {
        String m = Build.MANUFACTURER.toLowerCase(Locale.ROOT);
        String pkg = a.getPackageName();
        Intent[] tries;
        if (m.contains("meizu")) {
            tries = new Intent[] {new Intent("com.meizu.safe.security.SHOW_APPSEC")
                    .addCategory(Intent.CATEGORY_DEFAULT).putExtra("packageName", pkg)};
        } else if (m.contains("xiaomi") || m.contains("redmi") || m.contains("poco")) {
            tries = new Intent[] {new Intent().setClassName("com.miui.securitycenter",
                    "com.miui.permcenter.autostart.AutoStartManagementActivity")};
        } else if (m.contains("huawei") || m.contains("honor")) {
            tries = new Intent[] {new Intent().setClassName("com.huawei.systemmanager",
                    "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")};
        } else {
            tries = new Intent[0];
        }
        for (Intent i : tries) if (start(a, i)) return;
        start(a, new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + pkg)));
    }

    private static boolean granted(Context ctx, String p) {
        return ContextCompat.checkSelfPermission(ctx, p) == PackageManager.PERMISSION_GRANTED;
    }

    private static boolean start(Activity a, Intent i) {
        try {
            a.startActivity(i);
            return true;
        } catch (ActivityNotFoundException | SecurityException e) {
            return false;
        }
    }
}
