package yara.docscan.android.apk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Policy for Android packages - the APK counterpart of docscan-policy.yar: facts in, findings with a
 * severity and a human-readable text out. Heuristics on what the package asks for, not signatures
 * (signatures come from the vendor rules over classes.dex).
 */
public final class ApkInspector {
    public static final class Finding {
        public final String finding;
        public final String severity;   // HIGH / MEDIUM / INFO
        public final String text;

        public Finding(String finding, String severity, String text) {
            this.finding = finding;
            this.severity = severity;
            this.text = text;
        }

        @Override
        public String toString() {
            return finding + "(" + severity + ")";
        }
    }

    public static final class Report {
        public final List<Finding> findings;
        public final String verdict;

        Report(List<Finding> findings) {
            this.findings = Collections.unmodifiableList(findings);
            String v = "INFO";
            for (Finding f : findings) v = max(v, f.severity);
            this.verdict = v;
        }

        public List<String> names() {
            List<String> out = new ArrayList<>();
            for (Finding f : findings) out.add(f.finding);
            return out;
        }
    }

    static final Set<String> SMS = set(
            "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
            "android.permission.SEND_SMS", "android.permission.RECEIVE_MMS");
    static final String OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW";
    static final String INSTALL = "android.permission.REQUEST_INSTALL_PACKAGES";

    /** App stores whose installs are not "from a file". */
    static final Set<String> STORES = set(
            "com.android.vending", "com.google.android.packageinstaller.store",
            "com.huawei.appmarket", "com.xiaomi.market", "com.sec.android.app.samsungapps",
            "com.amazon.venezia", "com.meizu.mstore", "ru.vk.store", "org.fdroid.fdroid");

    private ApkInspector() {}

    public static Report inspect(ApkFacts f) {
        List<Finding> out = new ArrayList<>();
        if (!f.parsed) {
            out.add(new Finding("APK_MALFORMED", "MEDIUM",
                    "Маніфест APK не вдалося розібрати: пошкоджений або навмисно зіпсований пакет (ухилення від аналізу)"));
            return new Report(out);
        }

        if (!f.installed && f.samePackageInstalled && !f.signers.isEmpty()
                && !f.installedSigners.isEmpty() && Collections.disjoint(f.signers, f.installedSigners)) {
            out.add(new Finding("APK_IMPERSONATION", "HIGH",
                    "Пакет видає себе за встановлений застосунок " + f.packageName
                            + ", але підписаний іншим ключем — підробка"));
        }

        boolean sms = !Collections.disjoint(f.permissions, SMS);
        boolean overlay = f.permissions.contains(OVERLAY);

        if (f.accessibilityService && (overlay || sms || f.notificationListener || f.deviceAdmin)) {
            out.add(new Finding("APK_BANKER_PROFILE", "HIGH",
                    "Служба спеціальних можливостей разом з "
                            + join(overlay ? "показом поверх інших вікон" : null,
                                   sms ? "доступом до SMS" : null,
                                   f.notificationListener ? "читанням сповіщень" : null,
                                   f.deviceAdmin ? "правами адміністратора пристрою" : null)
                            + " — типовий набір банківського трояна / шпигуна"));
        }
        if (f.accessibilityService) {
            out.add(new Finding("APK_ACCESSIBILITY", "MEDIUM",
                    "Містить службу спеціальних можливостей: може читати екран і натискати замість користувача"));
        }
        if (sms) {
            out.add(new Finding("APK_SMS", "MEDIUM",
                    "Просить доступ до SMS: може перехоплювати коди підтвердження і надсилати платні SMS"));
        }
        if (f.deviceAdmin) {
            out.add(new Finding("APK_DEVICE_ADMIN", "MEDIUM",
                    "Просить права адміністратора пристрою: може блокувати екран, стирати дані, заважати видаленню"));
        }
        if (f.notificationListener) {
            out.add(new Finding("APK_NOTIFICATION_LISTENER", "INFO",
                    "Може читати всі сповіщення (зокрема коди з SMS і месенджерів)"));
        }
        if (overlay) {
            out.add(new Finding("APK_OVERLAY", "INFO", "Може показувати вікна поверх інших застосунків"));
        }
        if (f.permissions.contains(INSTALL)) {
            out.add(new Finding("APK_INSTALLER", "INFO", "Може встановлювати інші застосунки (завантажувач)"));
        }
        if (f.installed && !f.systemApp && (f.installer == null || !STORES.contains(f.installer))) {
            out.add(new Finding("APK_SIDELOADED", "INFO",
                    "Встановлено не з магазину застосунків" + (f.installer != null ? " (через " + f.installer + ")" : "")));
        }
        return new Report(out);
    }

    public static String max(String a, String b) {
        return rank(b) > rank(a) ? b : a;
    }

    public static int rank(String v) {
        if ("HIGH".equals(v)) return 2;
        if ("MEDIUM".equals(v)) return 1;
        return 0;
    }

    private static String join(String... parts) {
        List<String> p = new ArrayList<>();
        for (String s : parts) if (s != null) p.add(s);
        if (p.size() <= 1) return p.isEmpty() ? "" : p.get(0);
        return String.join(", ", p.subList(0, p.size() - 1)) + " і " + p.get(p.size() - 1);
    }

    private static Set<String> set(String... s) {
        return new HashSet<>(Arrays.asList(s));
    }
}
