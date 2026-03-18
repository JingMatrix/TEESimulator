package android.os;

/**
 * Stub for android.os.ServiceSpecificException.
 *
 * <p>Used by AIDL-generated binder stubs to report service-specific errors with numeric codes.
 * The binder framework serializes this as EX_SERVICE_SPECIFIC on the wire, preserving the integer
 * error code for the client.
 */
public class ServiceSpecificException extends RuntimeException {
    public final int errorCode;

    public ServiceSpecificException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ServiceSpecificException(int errorCode) {
        this(errorCode, null);
    }
}
