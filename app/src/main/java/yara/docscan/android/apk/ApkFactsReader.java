package yara.docscan.android.apk;

import android.Manifest;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.pm.ActivityInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.security.MessageDigest;
import java.util.Collections;
import java.util.Set;

/**
 * Reads {@link ApkFacts} through PackageManager: from an APK file (the framework's own manifest
 * parser - Java, in the app process) or from an installed package.
 */
public final class ApkFactsReader {
    private ApkFactsReader() {}

    @SuppressWarnings("deprecation")
    private static int flags() {
        int f = PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS;
        return f | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
    }

    /** Facts of an APK file, compared with the installed app of the same package name, if any. */
    public static ApkFacts fromFile(Context ctx, String path) {
        PackageManager pm = ctx.getPackageManager();
        ApkFacts f = new ApkFacts();
        PackageInfo pi;
        try {
            pi = pm.getPackageArchiveInfo(path, flags());
        } catch (RuntimeException e) {
            pi = null;
        }
        if (pi == null) return f;   // parsed = false
        if (pi.applicationInfo != null) {
            pi.applicationInfo.sourceDir = path;        // needed to load the label from the file
            pi.applicationInfo.publicSourceDir = path;
        }
        fill(pm, pi, f);
        try {
            PackageInfo inst = pm.getPackageInfo(pi.packageName, flags());
            f.samePackageInstalled = true;
            f.installedSigners.addAll(signers(inst));
        } catch (PackageManager.NameNotFoundException ignored) {
            // not installed
        }
        return f;
    }

    /** Facts of an installed package. */
    public static ApkFacts fromInstalled(Context ctx, String packageName) throws PackageManager.NameNotFoundException {
        PackageManager pm = ctx.getPackageManager();
        PackageInfo pi = pm.getPackageInfo(packageName, flags());
        ApkFacts f = new ApkFacts();
        fill(pm, pi, f);
        f.installed = true;
        ApplicationInfo ai = pi.applicationInfo;
        f.systemApp = ai != null && (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
        f.installer = installer(pm, packageName);
        return f;
    }

    @SuppressWarnings("deprecation")
    static String installer(PackageManager pm, String pkg) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                InstallSourceInfo s = pm.getInstallSourceInfo(pkg);
                return s.getInstallingPackageName();
            }
            return pm.getInstallerPackageName(pkg);
        } catch (Exception e) {
            return null;
        }
    }

    private static void fill(PackageManager pm, PackageInfo pi, ApkFacts f) {
        f.parsed = true;
        f.packageName = pi.packageName != null ? pi.packageName : "";
        f.versionName = pi.versionName != null ? pi.versionName : "";
        if (pi.applicationInfo != null) {
            f.targetSdk = pi.applicationInfo.targetSdkVersion;
            try {
                CharSequence l = pi.applicationInfo.loadLabel(pm);
                f.label = l != null ? l.toString() : "";
            } catch (RuntimeException ignored) {
                f.label = "";
            }
        }
        if (pi.requestedPermissions != null) Collections.addAll(f.permissions, pi.requestedPermissions);
        if (pi.services != null) {
            for (ServiceInfo s : pi.services) {
                if (Manifest.permission.BIND_ACCESSIBILITY_SERVICE.equals(s.permission)) f.accessibilityService = true;
                if (Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE.equals(s.permission)) f.notificationListener = true;
            }
        }
        if (pi.receivers != null) {
            for (ActivityInfo r : pi.receivers) {
                if (Manifest.permission.BIND_DEVICE_ADMIN.equals(r.permission)) f.deviceAdmin = true;
            }
        }
        f.signers.addAll(signers(pi));
    }

    @SuppressWarnings("deprecation")
    private static Set<String> signers(PackageInfo pi) {
        Signature[] sigs = null;
        if (Build.VERSION.SDK_INT >= 28) {
            SigningInfo si = pi.signingInfo;
            if (si != null) sigs = si.hasMultipleSigners() ? si.getApkContentsSigners() : si.getSigningCertificateHistory();
        } else {
            sigs = pi.signatures;
        }
        java.util.HashSet<String> out = new java.util.HashSet<>();
        if (sigs == null) return out;
        for (Signature s : sigs) {
            if (s == null) continue;
            try {
                byte[] d = MessageDigest.getInstance("SHA-256").digest(s.toByteArray());
                StringBuilder sb = new StringBuilder();
                for (byte b : d) sb.append(String.format("%02x", b));
                out.add(sb.toString());
            } catch (Exception ignored) {
                // no digest: unknown signer
            }
        }
        return out;
    }
}
