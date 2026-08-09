#include "binder/Binder.h"
#include "binder/BpBinder.h"
#include "binder/IInterface.h"
#include "binder/IPCThreadState.h"
#include "binder/IServiceManager.h"
#include "binder/RpcSession.h"
#include "binder/Status.h"

namespace android {

IInterface::IInterface() {}
IInterface::~IInterface() {}

IBinder::IBinder() {}
IBinder::~IBinder() {}
sp<IInterface> IBinder::queryLocalInterface(const String16 &) {
    return nullptr;
}
BBinder *IBinder::localBinder() {
    return nullptr;
}
BpBinder *IBinder::remoteBinder() {
    return nullptr;
}
bool IBinder::checkSubclass(const void *) const {
    return false;
}
void IBinder::withLock(const std::function<void()> &) {}

#ifdef __LP64__
static_assert(sizeof(IBinder) == 24);
static_assert(sizeof(BBinder) == 40);
#else
static_assert(sizeof(IBinder) == 12);
static_assert(sizeof(BBinder) == 20);
#endif

BBinder::BBinder() {}
BBinder::~BBinder() {}

const String16 &BBinder::getInterfaceDescriptor() const {
    __builtin_unreachable();
}
bool BBinder::isBinderAlive() const {
    return false;
}
status_t BBinder::pingBinder() {
    return 0;
}
status_t BBinder::dump(int, const Vector<String16> &) {
    return 0;
}
status_t BBinder::transact(uint32_t, const Parcel &, Parcel *, uint32_t) {
    return 0;
}
status_t BBinder::linkToDeath(const sp<DeathRecipient> &, void *, uint32_t) {
    return 0;
}
status_t BBinder::unlinkToDeath(const wp<DeathRecipient> &, void *, uint32_t, wp<DeathRecipient> *) {
    return 0;
}
void *BBinder::attachObject(const void *, void *, void *, object_cleanup_func) {
    return nullptr;
}
void *BBinder::findObject(const void *) const {
    return nullptr;
}
void *BBinder::detachObject(const void *) {
    return nullptr;
}
void BBinder::withLock(const std::function<void()> &) {}
BBinder *BBinder::localBinder() {
    return nullptr;
}
status_t BBinder::onTransact(uint32_t, const Parcel &, Parcel *, uint32_t) {
    return 0;
}

IPCThreadState *IPCThreadState::self() {
    return nullptr;
}
IPCThreadState *IPCThreadState::selfOrNull() {
    return nullptr;
}
pid_t IPCThreadState::getCallingPid() const {
    return 0;
}
const char *IPCThreadState::getCallingSid() const {
    return nullptr;
}
uid_t IPCThreadState::getCallingUid() const {
    return 0;
}

#ifdef __LP64__
static_assert(sizeof(Parcel) == 120);
#else
static_assert(sizeof(Parcel) == 60);
#endif

Parcel::Parcel() {}
Parcel::~Parcel() {}
const uint8_t *Parcel::data() const {
    return nullptr;
}
size_t Parcel::dataSize() const {
    return 0;
}
size_t Parcel::dataAvail() const {
    return 0;
}
size_t Parcel::dataPosition() const {
    return 0;
}
size_t Parcel::dataCapacity() const {
    return 0;
}
size_t Parcel::dataBufferSize() const {
    return 0;
}
status_t Parcel::setDataSize(size_t) {
    return 0;
}
void Parcel::setDataPosition(size_t) const {}
status_t Parcel::setDataCapacity(size_t) {
    return 0;
}
status_t Parcel::setData(const uint8_t *, size_t) {
    return 0;
}
status_t Parcel::appendFrom(const Parcel *, size_t, size_t) {
    return 0;
}
binder::Status Parcel::enforceNoDataAvail() const {
    return {};
}
void Parcel::setEnforceNoDataAvail(bool) {}
void Parcel::freeData() {}
status_t Parcel::write(const void *, size_t) {
    return 0;
}
void *Parcel::writeInplace(size_t) {
    return nullptr;
}
status_t Parcel::writeInt32(int32_t) {
    return 0;
}
status_t Parcel::writeUint32(uint32_t) {
    return 0;
}
status_t Parcel::writeInt64(int64_t) {
    return 0;
}
status_t Parcel::writeUint64(uint64_t) {
    return 0;
}
status_t Parcel::writeFloat(float) {
    return 0;
}
status_t Parcel::writeDouble(double) {
    return 0;
}
status_t Parcel::writeCString(const char *) {
    return 0;
}
status_t Parcel::writeString8(const char *, size_t) {
    return 0;
}
status_t Parcel::writeStrongBinder(const sp<IBinder> &) {
    return 0;
}
status_t Parcel::writeBool(bool) {
    return 0;
}
status_t Parcel::writeChar(char16_t) {
    return 0;
}
status_t Parcel::writeByte(int8_t) {
    return 0;
}
status_t Parcel::writeNoException() {
    return 0;
}
status_t Parcel::read(void *, size_t) const {
    return 0;
}
const void *Parcel::readInplace(size_t) const {
    return nullptr;
}
int32_t Parcel::readInt32() const {
    return 0;
}
status_t Parcel::readInt32(int32_t *) const {
    return 0;
}
uint32_t Parcel::readUint32() const {
    return 0;
}
status_t Parcel::readUint32(uint32_t *) const {
    return 0;
}
int64_t Parcel::readInt64() const {
    return 0;
}
status_t Parcel::readInt64(int64_t *) const {
    return 0;
}
uint64_t Parcel::readUint64() const {
    return 0;
}
status_t Parcel::readUint64(uint64_t *) const {
    return 0;
}
float Parcel::readFloat() const {
    return 0;
}
status_t Parcel::readFloat(float *) const {
    return 0;
}
double Parcel::readDouble() const {
    return 0;
}
status_t Parcel::readDouble(double *) const {
    return 0;
}
bool Parcel::readBool() const {
    return 0;
}
status_t Parcel::readBool(bool *) const {
    return 0;
}
char16_t Parcel::readChar() const {
    return 0;
}
status_t Parcel::readChar(char16_t *) const {
    return 0;
}
int8_t Parcel::readByte() const {
    return 0;
}
status_t Parcel::readByte(int8_t *) const {
    return 0;
}
sp<IBinder> Parcel::readStrongBinder() const {
    return nullptr;
}
status_t Parcel::readStrongBinder(sp<IBinder> *) const {
    return 0;
}
status_t Parcel::readNullableStrongBinder(sp<IBinder> *) const {
    return 0;
}
int32_t Parcel::readExceptionCode() const {
    return 0;
}
int Parcel::readFileDescriptor() const {
    return 0;
}

IServiceManager::IServiceManager() {}
IServiceManager::~IServiceManager() {}
const String16 &IServiceManager::getInterfaceDescriptor() const {
    __builtin_unreachable();
}
sp<IServiceManager> defaultServiceManager() {
    return nullptr;
}
void setDefaultServiceManager(const sp<IServiceManager> &) {}

} // namespace android
