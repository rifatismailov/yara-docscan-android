package yara.docscan.android.watch;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import yara.docscan.android.MainActivity;
import yara.docscan.android.R;

/** Notification channels: the ongoing "protection on" one and alerts. */
public final class Notifier {
    public static final String CH_SERVICE = "service";
    public static final String CH_THREATS = "threats";
    public static final String CH_DEVICE = "device";
    public static final int ID_SERVICE = 1;
    private static final int ID_THREATS_SUMMARY = 2;
    private static final String GROUP_THREATS = "threats";

    private Notifier() {}

    public static void createChannels(Context ctx) {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        NotificationChannel s = new NotificationChannel(CH_SERVICE, ctx.getString(R.string.ch_service),
                NotificationManager.IMPORTANCE_LOW);
        s.setShowBadge(false);
        nm.createNotificationChannel(s);
        nm.createNotificationChannel(new NotificationChannel(CH_THREATS, ctx.getString(R.string.ch_threats),
                NotificationManager.IMPORTANCE_HIGH));
        nm.createNotificationChannel(new NotificationChannel(CH_DEVICE, ctx.getString(R.string.ch_device),
                NotificationManager.IMPORTANCE_HIGH));
    }

    private static PendingIntent openApp(Context ctx, String tab) {
        Intent i = new Intent(ctx, MainActivity.class)
                .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP)
                .putExtra(MainActivity.EXTRA_TAB, tab);
        return PendingIntent.getActivity(ctx, tab.hashCode(), i,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    public static Notification service(Context ctx, String text) {
        return new NotificationCompat.Builder(ctx, CH_SERVICE)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(ctx.getString(R.string.service_title))
                .setContentText(text)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setContentIntent(openApp(ctx, MainActivity.TAB_OVERVIEW))
                .build();
    }

    public static void updateService(Context ctx, String text) {
        post(ctx, ID_SERVICE, service(ctx, text));
    }

    /** A file with a MEDIUM / HIGH verdict (what was found and what was done). */
    public static void fileThreat(Context ctx, String verdict, String name, String summary) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, CH_THREATS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(verdict + " · " + name)
                .setContentText(summary)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(summary))
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_ERROR)
                .setPriority("HIGH".equals(verdict) ? NotificationCompat.PRIORITY_HIGH : NotificationCompat.PRIORITY_DEFAULT)
                .setGroup(GROUP_THREATS)
                .setContentIntent(openApp(ctx, MainActivity.TAB_JOURNAL));
        post(ctx, ("file:" + name).hashCode(), b.build());
        postThreatSummary(ctx);
    }

    /** An installed app with a MEDIUM / HIGH verdict, with an "Uninstall" action (the user confirms). */
    public static void appThreat(Context ctx, String verdict, String pkg, String label, String summary) {
        Intent del = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + pkg));
        PendingIntent pDel = PendingIntent.getActivity(ctx, ("del:" + pkg).hashCode(), del,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, CH_THREATS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(verdict + " · " + ctx.getString(R.string.app_prefix) + " " + label)
                .setContentText(summary)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(summary))
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(openApp(ctx, MainActivity.TAB_JOURNAL))
                .setGroup(GROUP_THREATS)
                .addAction(0, ctx.getString(R.string.action_uninstall), pDel);
        post(ctx, ("app:" + pkg).hashCode(), b.build());
        postThreatSummary(ctx);
    }

    /** The group header: a sweep that finds many threats shows one expandable notification. */
    private static void postThreatSummary(Context ctx) {
        Notification n = new NotificationCompat.Builder(ctx, CH_THREATS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(ctx.getString(R.string.threats_summary))
                .setGroup(GROUP_THREATS)
                .setGroupSummary(true)
                .setGroupAlertBehavior(NotificationCompat.GROUP_ALERT_CHILDREN)
                .setAutoCancel(true)
                .setContentIntent(openApp(ctx, MainActivity.TAB_JOURNAL))
                .build();
        post(ctx, ID_THREATS_SUMMARY, n);
    }

    /** A change of the device security (an accessibility service turned on ...). */
    public static void device(Context ctx, String title, String text) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, CH_DEVICE)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(text))
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(openApp(ctx, MainActivity.TAB_OVERVIEW));
        post(ctx, ("dev:" + title).hashCode(), b.build());
    }

    @SuppressWarnings("MissingPermission")
    private static void post(Context ctx, int id, Notification n) {
        try {
            NotificationManagerCompat.from(ctx).notify(id, n);
        } catch (SecurityException ignored) {
            // POST_NOTIFICATIONS not granted (Android 13+): the journal still has it
        }
    }
}
