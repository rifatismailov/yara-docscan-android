package yara.docscan.android.scan;

/** JNI entry points of libyaradocscan.so (app/src/main/cpp/docscan_jni.c). */
final class NativeYara {
    static {
        System.loadLibrary("yaradocscan");
    }

    private NativeYara() {}

    /** Compiles a rules index (includes resolved relative to it); returns a native handle. */
    static native long compile(String indexPath) throws DocScanException;

    /** Saves compiled rules (yarac format). */
    static native boolean save(long rules, String path);

    /** Loads rules saved by {@link #save} from an open descriptor; 0 if missing or incompatible. */
    static native long loadFd(int fd);

    static native void destroy(long rules);

    static native String version();

    /**
     * Scans an open file descriptor (ownership stays with the caller).
     *
     * @param name        document display name (THOR/LOKI {@code filename} variable)
     * @param dir         folder of the document or "" ({@code filepath} variable)
     * @param timeout     seconds, 0 = none
     * @param planDisarm  when the policy asks for a cure, plan it ({@code disarm_result} in the JSON)
     * @param curedOutFd  where the cured file is written (DISARM_REPLACE), -1 = none
     * @param macroOutFd  where the decompressed VBA is written (the macro store), -1 = none
     * @return the docscan JSON object as UTF-8 bytes
     */
    static native byte[] scanFd(long rules, int fd, String name, String dir, int timeout,
                                boolean planDisarm, int curedOutFd, int macroOutFd) throws DocScanException;

    /**
     * Pass 3 (critical information): text of the document vs the critical rules; on a match the queue
     * line (JSON schema 2.0) goes to outFd. chunkSize 0 / chunkOverlap -1 = rule meta or 700/120.
     * @return status JSON: {"status":"queued","fragments":N,"rules":[..]} / nomatch / skipped / error
     */
    static native byte[] critical(long rules, int fd, String name, String path, int chunkSize,
                                  int chunkOverlap, int timeout, int outFd) throws DocScanException;

    /** Vendor rules over a buffer (classes.dex of an APK): {"rules":[..],"descriptions":[..]}. */
    static native byte[] scanMem(long rules, byte[] data, int len, String name, int timeout)
            throws DocScanException;
}
