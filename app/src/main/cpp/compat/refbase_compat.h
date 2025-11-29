#pragma once

namespace android {

// Forward-declare the RefBase class.
class RefBase;

// Declares our compatibility function.
void incStrongFromExisting(const RefBase *ref, const void *id);

} // namespace android
