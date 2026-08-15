package android.content.pm;

import android.content.Intent;
import android.os.IBinder;

public interface IPackageManager {
    String[] getPackagesForUid(int uid);

    PackageInfo getPackageInfo(String packageName, long flags, int userId);

    PackageInfo getPackageInfo(String packageName, int flags, int userId);

    // The `flags` argument widened from int to long in Android 13 (T), so every bulk/per-user call
    // below is declared twice and picked by SDK level; calling the wrong one lands on a
    // NoSuchMethodError, which the daemon catches and retries with the other.
    ApplicationInfo getApplicationInfo(String packageName, long flags, int userId);

    ApplicationInfo getApplicationInfo(String packageName, int flags, int userId);

    ParceledListSlice<ApplicationInfo> getInstalledApplications(long flags, int userId);

    ParceledListSlice<ApplicationInfo> getInstalledApplications(int flags, int userId);

    ParceledListSlice<ResolveInfo> queryIntentActivities(
            Intent intent, String resolvedType, long flags, int userId);

    ParceledListSlice<ResolveInfo> queryIntentActivities(
            Intent intent, String resolvedType, int flags, int userId);

    class Stub {
        public static IPackageManager asInterface(IBinder binder) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
