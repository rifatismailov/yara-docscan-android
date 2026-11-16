package yara.docscan.android.apk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ApkInspectorTest {
    private static ApkFacts parsed() {
        ApkFacts f = new ApkFacts();
        f.parsed = true;
        f.packageName = "com.example";
        return f;
    }

    @Test
    public void plainAppIsInfo() {
        ApkFacts f = parsed();
        f.permissions.add("android.permission.INTERNET");
        ApkInspector.Report r = ApkInspector.inspect(f);
        assertEquals("INFO", r.verdict);
        assertTrue(r.findings.isEmpty());
    }

    @Test
    public void malformedManifestIsMedium() {
        ApkInspector.Report r = ApkInspector.inspect(new ApkFacts());
        assertEquals("MEDIUM", r.verdict);
        assertEquals("APK_MALFORMED", r.findings.get(0).finding);
    }

    @Test
    public void bankerProfileIsHigh() {
        ApkFacts f = parsed();
        f.accessibilityService = true;
        f.permissions.add("android.permission.RECEIVE_SMS");
        f.permissions.add("android.permission.SYSTEM_ALERT_WINDOW");
        ApkInspector.Report r = ApkInspector.inspect(f);
        assertEquals("HIGH", r.verdict);
        assertTrue(r.names().contains("APK_BANKER_PROFILE"));
        assertTrue(r.names().contains("APK_SMS"));
    }

    @Test
    public void accessibilityAloneIsMedium() {
        ApkFacts f = parsed();
        f.accessibilityService = true;
        assertEquals("MEDIUM", ApkInspector.inspect(f).verdict);
    }

    @Test
    public void impersonationNeedsDifferentSigners() {
        ApkFacts f = parsed();
        f.samePackageInstalled = true;
        f.signers.add("aa");
        f.installedSigners.add("bb");
        assertEquals("HIGH", ApkInspector.inspect(f).verdict);

        f.installedSigners.add("aa");   // an update signed by the same key
        assertFalse(ApkInspector.inspect(f).names().contains("APK_IMPERSONATION"));

        ApkFacts unknown = parsed();    // signers unknown: no claim
        unknown.samePackageInstalled = true;
        assertFalse(ApkInspector.inspect(unknown).names().contains("APK_IMPERSONATION"));
    }

    @Test
    public void sideloadedOnlyForInstalledNonSystemApps() {
        ApkFacts f = parsed();
        f.installed = true;
        f.installer = null;
        assertTrue(ApkInspector.inspect(f).names().contains("APK_SIDELOADED"));
        f.installer = "com.android.vending";
        assertFalse(ApkInspector.inspect(f).names().contains("APK_SIDELOADED"));
        f.installer = null;
        f.systemApp = true;
        assertFalse(ApkInspector.inspect(f).names().contains("APK_SIDELOADED"));
    }
}
