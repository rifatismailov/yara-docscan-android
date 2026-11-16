package yara.docscan.android.scan;

/** Rule compilation or scan failure reported by the native layer. */
public class DocScanException extends Exception {
    public DocScanException(String message) {
        super(message);
    }

    public DocScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
