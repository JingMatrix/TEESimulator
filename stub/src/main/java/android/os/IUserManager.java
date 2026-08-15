package android.os;

import android.content.pm.UserInfo;
import java.util.List;

public interface IUserManager {
    // Android 11 (R) and later. Android 10 has the single-argument form below instead, so a caller
    // must pick by SDK level and be ready for a NoSuchMethodError when a ROM disagrees.
    List<UserInfo> getUsers(boolean excludePartial, boolean excludeDying, boolean excludePreCreated);

    List<UserInfo> getUsers(boolean excludeDying);

    UserInfo getUserInfo(int userId);

    class Stub {
        public static IUserManager asInterface(IBinder binder) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
