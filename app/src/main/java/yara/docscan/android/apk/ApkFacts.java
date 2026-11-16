package yara.docscan.android.apk;

import java.util.HashSet;
import java.util.Set;

/** What the manifest / PackageManager tells about an APK - plain data, so the policy is JVM-testable. */
public final class ApkFacts {
    /** false: the manifest could not be parsed (getPackageArchiveInfo returned null). */
    public boolean parsed;
    public String packageName = "";
    public String label = "";
    public String versionName = "";
    public int targetSdk;
    public final Set<String> permissions = new HashSet<>();

    public boolean accessibilityService;    // a service protected by BIND_ACCESSIBILITY_SERVICE
    public boolean notificationListener;    // ... BIND_NOTIFICATION_LISTENER_SERVICE
    public boolean deviceAdmin;             // a receiver protected by BIND_DEVICE_ADMIN

    /** SHA-256 of the signing certificates (hex); empty when unknown. */
    public final Set<String> signers = new HashSet<>();

    // ---- a file APK compared with the installed apps
    /** An app with the same package name is installed. */
    public boolean samePackageInstalled;
    /** ... and its signers (empty when unknown). */
    public final Set<String> installedSigners = new HashSet<>();

    // ---- an installed app
    public boolean installed;
    public boolean systemApp;
    /** The installer package; null = installed from a file (adb / file manager / browser). */
    public String installer;
}
