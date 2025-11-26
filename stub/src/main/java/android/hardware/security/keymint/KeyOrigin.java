package android.hardware.security.keymint;

public @interface KeyOrigin {
    int GENERATED = 0;
    int DERIVED = 1;
    int IMPORTED = 2;
    int RESERVED = 3;
    int SECURELY_IMPORTED = 4;
}
