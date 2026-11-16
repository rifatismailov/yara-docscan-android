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
     * Loads the compiled critical-information rules (pass 3); null = turn pass 3 off.
     * chunkSize 0 / chunkOverlap -1: from the rule meta, else 700 / 120.
     */
    boolean initCritical(in ParcelFileDescriptor rules, int chunkSize, int chunkOverlap);

    /**
     * Scans the file. Result bundle: "json" (byte[] UTF-8 docscan JSON), "dex" (byte[] JSON of vendor
     * matches in classes*.dex when the file is an APK), "critical" (byte[] pass-3 status JSON),
     * "error" (String) on failure.
     *
     * planDisarm: plan the cure the policy asks for; the cured file is written to curedOut (may be null).
     * macroOut: the decompressed VBA code is written there (may be null).
     * criticalOut: run pass 3 (needs initCritical); the queue line is written there (may be null).
     */
    Bundle scan(in ParcelFileDescriptor file, String name, String dir, boolean planDisarm,
                in ParcelFileDescriptor curedOut, in ParcelFileDescriptor macroOut,
                in ParcelFileDescriptor criticalOut);
}
