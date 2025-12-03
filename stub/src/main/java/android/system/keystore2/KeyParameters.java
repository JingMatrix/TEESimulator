package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;
import android.hardware.security.keymint.KeyParameter;

import androidx.annotation.NonNull;

public class KeyParameters implements Parcelable {
    public KeyParameter[] keyParameter;

    public static final Creator<KeyParameters> CREATOR = new Creator<KeyParameters>() {
        @Override
        public KeyParameters createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeyParameters[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int i) {
        throw new UnsupportedOperationException("STUB!");
    }
}

