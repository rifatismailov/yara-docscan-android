package yara.docscan.android.scan;

/**
 * The sandboxed scan worker (IsolatedScanService, android:isolatedProcess="true").
 *
 * The Android counterpart of the Windows broker / worker split of yara-docscan: the worker parses the
 * hostile file from a descriptor and touches no file; the app process (broker) parses nothing and does
 * every file operation (backup, replace, delete, quarantine).
 */
interface IScanWorker {
    /** Loads compiled rules (.yarc) from the descriptor. Returns the YARA version, or null on failure. */
    String init(in ParcelFileDescriptor rules);

    /**
     * Scans the file. Result bundle: "json" (byte[] UTF-8 docscan JSON), "dex" (byte[] JSON of vendor
     * matches in classes*.dex when the file is an APK), "error" (String) on failure.
     *
     * planDisarm: plan the cure the policy asks for; the cured file is written to curedOut (may be null).
     */
    Bundle scan(in ParcelFileDescriptor file, String name, String dir, boolean planDisarm,
                in ParcelFileDescriptor curedOut);
}
