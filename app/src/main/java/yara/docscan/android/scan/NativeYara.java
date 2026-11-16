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

    /** Loads rules saved by {@link #save}; 0 if the file is missing or incompatible. */
    static native long load(String path);

    static native void destroy(long rules);

    static native String version();

    /**
     * Scans an open file descriptor (ownership stays with the caller).
     *
     * @param name    document display name (THOR/LOKI {@code filename} variable)
     * @param dir     folder of the document or "" ({@code filepath} variable)
     * @param timeout seconds, 0 = none
     * @return the docscan JSON object as UTF-8 bytes
     */
    static native byte[] scanFd(long rules, int fd, String name, String dir, int timeout)
            throws DocScanException;
}
