package android.content.pm;

import java.util.List;

/**
 * The chunked list wrapper every bulk IPackageManager call returns. Declared raw (the framework
 * class is generic over Parcelable) because the daemon only ever calls getList() and casts.
 */
public class ParceledListSlice<T> {
    public List<T> getList() {
        throw new UnsupportedOperationException("STUB!");
    }
}
