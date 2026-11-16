package yara.docscan.android.watch;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Which files the watcher scans: the $DocExt / $GenExt lists of docscan-watcher.ps1 plus Android
 * packages, and which paths it never looks at ($ExcludePattern).
 */
public final class WatchFilter {
    public static final String DOCUMENT = "document";
    public static final String GENERAL = "general";
    public static final String APK = "apk";

    static final Set<String> DOC_EXT = set(
            ".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm",
            ".xls", ".xlt", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb",
            ".ppt", ".pps", ".pot", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
            ".xla", ".xlam", ".ppa", ".ppam",
            ".rtf", ".pdf", ".lnk",
            ".one",
            ".iqy", ".slk");

    static final Set<String> GEN_EXT = set(
            ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".msi",
            ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".jar",
            ".xll", ".msc", ".url", ".svg", ".htm", ".html",
            ".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx",
            // Android
            ".dex", ".apks", ".xapk", ".apkm");

    static final Set<String> APK_EXT = set(".apk");

    /** Archives whose documents / packages the docscan module inspects (the $isZip of the PC watcher). */
    static final Set<String> ARCHIVE_EXT = set(".zip", ".apks", ".xapk", ".apkm");

    /** Relative to the storage root. */
    private static final Pattern[] EXCLUDE = {
            Pattern.compile("^Android/(data|obb)(/|$)"),          // other apps' private files (no access anyway)
            Pattern.compile("(^|/)\\.[^/]*"),                    // hidden: .thumbnails, .trash, .pending-*, ...
            Pattern.compile("\\.docscan-(bak|tmp)$"),             // our own backups / temp files
            Pattern.compile("(^|/)~\\$[^/]*$"),                   // Office lock files
            Pattern.compile("(^|/)LOST\\.DIR(/|$)"),
    };

    private WatchFilter() {}

    /** "document", "general", "apk" or null when the file is not scanned. */
    public static String category(String name) {
        String ext = ext(name);
        if (DOC_EXT.contains(ext)) return DOCUMENT;
        if (APK_EXT.contains(ext)) return APK;
        if (GEN_EXT.contains(ext)) return GENERAL;
        return null;
    }

    public static boolean isArchiveExt(String name) {
        return ARCHIVE_EXT.contains(ext(name));
    }

    /** @param relative path relative to the watched root, '/'-separated */
    public static boolean isExcluded(String relative) {
        for (Pattern p : EXCLUDE) if (p.matcher(relative).find()) return true;
        return false;
    }

    public static String ext(String name) {
        int slash = name.lastIndexOf('/');
        int dot = name.lastIndexOf('.');
        if (dot <= slash + 1) return "";   // no dot, or a leading dot only (".profile")
        return name.substring(dot).toLowerCase(Locale.ROOT);
    }

    private static Set<String> set(String... s) {
        return new HashSet<>(Arrays.asList(s));
    }
}
