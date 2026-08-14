package android.content.pm;

/** The framework's per-user record. Only the three fields the daemon reads are declared. */
public class UserInfo {
    public static final int FLAG_MANAGED_PROFILE = 0x00000020;

    public int id;
    public String name;
    public int flags;
}
