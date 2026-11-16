package yara.docscan.android.scan;

import java.io.File;
import java.io.IOException;

/**
 * The APPLY half of docscan_disarm (libyara/modules/docscan/disarm.c, docscan_disarm_apply) in the
 * broker: the worker planned the cure in memory; here only file operations happen. Same rules: never
 * change or delete a file whose backup could not be written; the same action strings.
 */
public final class Disarm {
    private Disarm() {}

    /**
     * Carries out the plan of {@code result} on {@code target}.
     *
     * @param cured the file the worker wrote the cured document to (DISARM_REPLACE)
     * @return the final action ("removed:vbaProject.bin", "quarantined", "failed:backup", ...) or null
     *         when nothing was planned
     */
    public static String apply(File target, ScanResult result, File cured, Quarantine q, String summary) {
        int kind = result.disarmKind;
        String plan = result.disarmAction == null ? "" : result.disarmAction;
        if (kind == ScanResult.DISARM_NOT_PLANNED) return null;
        if (kind == ScanResult.DISARM_NONE || kind == ScanResult.DISARM_FAILED) {
            return kind == ScanResult.DISARM_FAILED && plan.isEmpty() ? "failed" : plan;
        }

        File bak;
        try {
            bak = q.backup(target);
        } catch (IOException e) {
            return "failed:backup";
        }
        q.writeMeta(bak, target.getPath(), plan, result.verdict.name(), summary);

        if (kind == ScanResult.DISARM_DELETE) {
            return target.delete() ? plan : "failed:delete";
        }
        return replace(target, cured) ? plan : "failed:replace";
    }

    /** Quarantine a whole file (an APK, a general file): backup, then delete. */
    public static String quarantine(File target, Quarantine q, String verdict, String summary) {
        File bak;
        try {
            bak = q.backup(target);
        } catch (IOException e) {
            return "failed:quarantine";
        }
        q.writeMeta(bak, target.getPath(), "quarantined", verdict, summary);
        return target.delete() ? "quarantined" : "failed:quarantine";
    }

    /** Through "&lt;file&gt;.docscan-tmp" next to the original, as disarm.c does. */
    private static boolean replace(File target, File cured) {
        if (cured == null || !cured.isFile()) return false;
        File tmp = new File(target.getPath() + ".docscan-tmp");
        try {
            Quarantine.copy(cured, tmp);
        } catch (IOException e) {
            tmp.delete();
            return false;
        }
        if (!target.delete()) {
            tmp.delete();     // original still in place
            return false;
        }
        return tmp.renameTo(target);   // on failure the cured copy stays as <file>.docscan-tmp
    }
}
