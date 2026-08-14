// The control-channel server: it owns the abstract unix socket @teesim, accepts
// the daemon's connection, and turns each pushed "config" message into calls on
// the router's staging API. See control.h for the protocol shape.
//
// Pure POSIX + the JSON reader + the staging API, so the same object file links
// into both interceptors (which are built with -fno-exceptions/-fno-rtti); it
// touches no binder or android headers beyond the property read.

#include "control.h"

#include <pthread.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "json.hpp"
#include "logging.hpp"

namespace {

// Abstract socket: sun_path[0] == '\0', then these bytes. One daemon, one
// keystore, so a single well-known name suffices.
constexpr const char kSocketName[] = "teesim";
constexpr size_t kSocketNameLen = sizeof(kSocketName) - 1;
constexpr size_t kMaxFrame = 8u * 1024 * 1024;

// Decode standard base64 (padding optional; whitespace ignored). Returns false
// on any invalid character.
bool Base64Decode(const std::string &in, std::vector<uint8_t> &out) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  out.clear();
  out.reserve(in.size() / 4 * 3 + 3);
  uint32_t buf = 0;
  int bits = 0;
  for (char c : in) {
    if (c == '=') break;
    if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
    int v = val(c);
    if (v < 0) return false;
    buf = (buf << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
    }
  }
  return true;
}

// Standard base64 encode, for handing re-signed certificates back to the daemon.
std::string Base64Encode(const uint8_t *data, size_t len) {
  static const char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve((len + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 3 <= len; i += 3) {
    uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
    out.push_back(kTable[(n >> 18) & 63]);
    out.push_back(kTable[(n >> 12) & 63]);
    out.push_back(kTable[(n >> 6) & 63]);
    out.push_back(kTable[n & 63]);
  }
  if (i < len) {
    bool two = (i + 1 < len);
    uint32_t n = (uint32_t(data[i]) << 16) | (two ? uint32_t(data[i + 1]) << 8 : 0);
    out.push_back(kTable[(n >> 18) & 63]);
    out.push_back(kTable[(n >> 12) & 63]);
    out.push_back(two ? kTable[(n >> 6) & 63] : '=');
    out.push_back('=');
  }
  return out;
}

int AndroidApi() {
  char buf[PROP_VALUE_MAX] = {0};
  if (__system_property_get("ro.build.version.sdk", buf) > 0) return atoi(buf);
  return 0;
}

bool ReadFull(int fd, void *p, size_t n) {
  uint8_t *b = static_cast<uint8_t *>(p);
  while (n > 0) {
    ssize_t r = read(fd, b, n);
    if (r <= 0) return false;
    b += r;
    n -= static_cast<size_t>(r);
  }
  return true;
}

bool WriteFull(int fd, const void *p, size_t n) {
  const uint8_t *b = static_cast<const uint8_t *>(p);
  while (n > 0) {
    ssize_t w = write(fd, b, n);
    if (w <= 0) return false;
    b += w;
    n -= static_cast<size_t>(w);
  }
  return true;
}

// One length-prefixed frame: [u32 big-endian length][UTF-8 JSON].
bool ReadFrame(int fd, std::string &out) {
  uint8_t hdr[4];
  if (!ReadFull(fd, hdr, 4)) return false;
  uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) |
                 (uint32_t(hdr[2]) << 8) | uint32_t(hdr[3]);
  if (len == 0 || len > kMaxFrame) return false;
  out.resize(len);
  return ReadFull(fd, &out[0], len);
}

bool WriteFrame(int fd, const std::string &payload) {
  uint32_t len = static_cast<uint32_t>(payload.size());
  uint8_t hdr[4] = {uint8_t(len >> 24), uint8_t(len >> 16), uint8_t(len >> 8),
                    uint8_t(len)};
  return WriteFull(fd, hdr, 4) && WriteFull(fd, payload.data(), payload.size());
}

// Owns the decoded byte spans a TsProfile points into, for the lifetime of one
// teesim_cfg_add_profile call.
struct ProfileStorage {
  std::string id;
  std::string mode;
  std::vector<uint8_t> keybox;
  std::vector<std::string> pkg_strings;
  std::vector<const char *> pkg_ptrs;
  std::vector<int32_t> uids;
  std::string brand, device, product, serial, imei, imei2, meid, manufacturer, model;
  TsDeviceIds ids{};
  bool has_ids = false;
};

// Populate a TsDeviceIds from an optional "deviceIds" object, keeping the string
// bytes in `s`. Returns true if at least one id is present.
bool FillDeviceIds(const tjson::Value &obj, ProfileStorage &s) {
  auto field = [&](const char *key, std::string &dst, const uint8_t *&ptr, size_t &len) {
    const tjson::Value *v = obj.get(key);
    if (v && v->is_string()) dst = v->as_string();
    ptr = reinterpret_cast<const uint8_t *>(dst.data());
    len = dst.size();
  };
  field("brand", s.brand, s.ids.brand, s.ids.brand_len);
  field("device", s.device, s.ids.device, s.ids.device_len);
  field("product", s.product, s.ids.product, s.ids.product_len);
  field("serial", s.serial, s.ids.serial, s.ids.serial_len);
  field("imei", s.imei, s.ids.imei, s.ids.imei_len);
  field("imei2", s.imei2, s.ids.imei2, s.ids.imei2_len);
  field("meid", s.meid, s.ids.meid, s.ids.meid_len);
  field("manufacturer", s.manufacturer, s.ids.manufacturer, s.ids.manufacturer_len);
  field("model", s.model, s.ids.model, s.ids.model_len);
  return !(s.brand.empty() && s.device.empty() && s.product.empty() &&
           s.serial.empty() && s.imei.empty() && s.imei2.empty() && s.meid.empty() &&
           s.manufacturer.empty() && s.model.empty());
}

// Apply one parsed "config" message. Writes the ack counts through the outparams.
void ApplyConfig(const tjson::Value &msg, uint64_t &epoch, int &applied, int &total) {
  epoch = 0;
  applied = 0;
  total = 0;
  if (const tjson::Value *e = msg.get("epoch")) epoch = static_cast<uint64_t>(e->as_int(0));

  // Device-wide boot info.
  std::vector<uint8_t> vb_key, vb_hash, module_hash;
  TsBootInfo boot{};
  if (const tjson::Value *bi = msg.get("bootInfo")) {
    if (const tjson::Value *k = bi->get("verifiedBootKey")) Base64Decode(k->as_string(), vb_key);
    if (const tjson::Value *h = bi->get("verifiedBootHash")) Base64Decode(h->as_string(), vb_hash);
    if (const tjson::Value *m = bi->get("moduleHash")) Base64Decode(m->as_string(), module_hash);
    boot.device_locked = bi->get("deviceLocked") ? bi->get("deviceLocked")->as_bool(true) : true;
    boot.verified_boot_state =
        bi->get("verifiedBootState") ? int32_t(bi->get("verifiedBootState")->as_int(0)) : 0;
    boot.strongbox_available =
        bi->get("strongBoxAvailable") ? bi->get("strongBoxAvailable")->as_bool(false) : false;
    boot.attest_version_tee =
        bi->get("attestVersionTee") ? int32_t(bi->get("attestVersionTee")->as_int(400)) : 400;
    boot.attest_version_strongbox = bi->get("attestVersionStrongBox")
                                        ? int32_t(bi->get("attestVersionStrongBox")->as_int(400))
                                        : boot.attest_version_tee;
  } else {
    boot.device_locked = true;
    boot.attest_version_tee = 400;
    boot.attest_version_strongbox = 400;
  }
  boot.verified_boot_key = vb_key.data();
  boot.verified_boot_key_len = vb_key.size();
  boot.verified_boot_hash = vb_hash.data();
  boot.verified_boot_hash_len = vb_hash.size();
  boot.module_hash = module_hash.data();
  boot.module_hash_len = module_hash.size();
  teesim_cfg_begin(&boot);

  const tjson::Value *profiles = msg.get("profiles");
  if (profiles && profiles->is_array()) {
    total = static_cast<int>(profiles->size());
    for (size_t i = 0; i < profiles->size(); ++i) {
      const tjson::Value &pj = profiles->at(i);
      ProfileStorage s;
      s.id = pj.get("id") ? pj.get("id")->as_string() : std::string();
      s.mode = pj.get("mode") ? pj.get("mode")->as_string() : std::string();
      if (const tjson::Value *kb = pj.get("keyboxB64")) {
        if (!Base64Decode(kb->as_string(), s.keybox)) {
          LOGE("control: profile %s has an undecodable keybox", s.id.c_str());
          continue;
        }
      }
      if (const tjson::Value *pkgs = pj.get("packages")) {
        for (size_t j = 0; j < pkgs->size(); ++j) s.pkg_strings.push_back(pkgs->at(j).as_string());
      }
      s.pkg_ptrs.reserve(s.pkg_strings.size());
      for (const auto &p : s.pkg_strings) s.pkg_ptrs.push_back(p.c_str());
      if (const tjson::Value *uids = pj.get("uids")) {
        for (size_t j = 0; j < uids->size(); ++j)
          s.uids.push_back(static_cast<int32_t>(uids->at(j).as_int(-1)));
      }
      if (const tjson::Value *ids = pj.get("deviceIds")) s.has_ids = FillDeviceIds(*ids, s);

      TsProfile tp{};
      tp.id = s.id.c_str();
      tp.keybox = s.keybox.data();
      tp.keybox_len = s.keybox.size();
      tp.mode = s.mode.empty() ? nullptr : s.mode.c_str();
      tp.security_level = pj.get("securityLevel") ? int32_t(pj.get("securityLevel")->as_int(1)) : 1;
      tp.os_version = pj.get("osVersion") ? uint32_t(pj.get("osVersion")->as_int(0)) : 0;
      tp.os_patchlevel = pj.get("osPatchLevel") ? uint32_t(pj.get("osPatchLevel")->as_int(0)) : 0;
      tp.vendor_patchlevel =
          pj.get("vendorPatchLevel") ? uint32_t(pj.get("vendorPatchLevel")->as_int(0)) : 0;
      tp.boot_patchlevel =
          pj.get("bootPatchLevel") ? uint32_t(pj.get("bootPatchLevel")->as_int(0)) : 0;
      tp.ids = s.has_ids ? &s.ids : nullptr;
      tp.packages = s.pkg_ptrs.data();
      tp.n_packages = static_cast<int>(s.pkg_ptrs.size());
      tp.uids = s.uids.data();
      tp.n_uids = static_cast<int>(s.uids.size());

      if (teesim_cfg_add_profile(&tp)) ++applied;
    }
  }
  char err[128] = {0};
  int committed = teesim_cfg_commit(epoch, err, sizeof(err));
  if (committed < 0) LOGE("control: commit failed: %s", err);
}

std::string BuildHello() {
  std::string s = "{\"type\":\"hello\",\"role\":\"lib\",\"protocol\":1,\"hook\":\"";
  s += teesim_hook_name();
  s += "\",\"androidApi\":";
  s += std::to_string(AndroidApi());
  s += ",\"keystorePid\":";
  s += std::to_string(getpid());
  s += "}";
  return s;
}

std::string BuildAck(uint64_t epoch, int applied, int total) {
  std::string s = "{\"type\":\"ack\",\"epoch\":";
  s += std::to_string(epoch);
  s += ",\"ok\":true,\"profilesApplied\":";
  s += std::to_string(applied);
  s += ",\"profilesFailed\":";
  s += std::to_string(total - applied);
  s += "}";
  return s;
}

// Serve one accepted daemon connection until it closes.
void HandleConnection(int fd) {
  // Auth: only root (the daemon) may push config.
  struct ucred cred{};
  socklen_t clen = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0 || cred.uid != 0) {
    LOGE("control: rejecting non-root peer uid=%d", cred.uid);
    close(fd);
    return;
  }
  WriteFrame(fd, BuildHello());

  std::string frame;
  while (ReadFrame(fd, frame)) {
    tjson::Value msg;
    if (!tjson::parse(frame.data(), frame.size(), msg)) {
      LOGE("control: dropping unparseable frame (%zu bytes)", frame.size());
      continue;
    }
    const tjson::Value *type = msg.get("type");
    std::string t = type ? type->as_string() : std::string();
    if (t == "config") {
      uint64_t epoch = 0;
      int applied = 0, total = 0;
      ApplyConfig(msg, epoch, applied, total);
      WriteFrame(fd, BuildAck(epoch, applied, total));
      LOGI("control: applied config epoch=%llu profiles=%d/%d",
           static_cast<unsigned long long>(epoch), applied, total);
    } else if (t == "resign") {
      // Re-sign one existing key's attestation leaf under its profile's keybox. The daemon sends the
      // leaf and the owning profile id; we return the patched chain (base64 DER per cert) for it to
      // write back with updateSubcomponent.
      const tjson::Value *pid = msg.get("profile");
      const tjson::Value *lb = msg.get("leafB64");
      std::string profile = pid ? pid->as_string() : std::string();
      std::vector<uint8_t> leaf;
      // Accumulate the chain as a JSON array body via the cert sink (captureless -> C callback).
      struct SinkCtx {
        std::string certs;
        bool first = true;
      } sc;
      auto sink = [](void *ctx, const uint8_t *der, size_t len) {
        auto *s = static_cast<SinkCtx *>(ctx);
        if (!s->first) s->certs += ",";
        s->first = false;
        s->certs += '"';
        s->certs += Base64Encode(der, len);
        s->certs += '"';
      };
      bool ok = false;
      if (lb && !profile.empty() && Base64Decode(lb->as_string(), leaf) && !leaf.empty()) {
        ok = teesim_cfg_resign(profile.c_str(), leaf.data(), leaf.size(), sink, &sc);
      }
      std::string resp = "{\"type\":\"resigned\",\"ok\":";
      resp += ok ? "true" : "false";
      resp += ",\"chainB64\":[";
      resp += sc.certs;
      resp += "]}";
      WriteFrame(fd, resp);
    } else if (t == "getUsage") {
      // Poll the router's per-caller key-usage snapshot (see control.h). The router owns the JSON
      // array; we wrap it in the reply envelope and free it.
      char* j = teesim_usage_json_alloc();
      std::string resp = "{\"type\":\"usage\",\"apps\":";
      resp += (j ? j : "[]");
      resp += "}";
      free(j);
      WriteFrame(fd, resp);
    } else if (t == "ping") {
      const tjson::Value *e = msg.get("epoch");
      std::string pong = "{\"type\":\"pong\",\"epoch\":";
      pong += std::to_string(e ? e->as_int(0) : 0);
      pong += "}";
      WriteFrame(fd, pong);
    }
    // "hello" and unknown types are ignored (forward-compat).
  }
  close(fd);
}

void *ServerThread(void *) {
  int srv = socket(AF_UNIX, SOCK_STREAM, 0);
  if (srv < 0) {
    LOGE("control: socket() failed: %s", strerror(errno));
    return nullptr;
  }
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';  // abstract namespace
  memcpy(addr.sun_path + 1, kSocketName, kSocketNameLen);
  socklen_t alen = static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) + 1 + kSocketNameLen);

  // The previous keystore may still own the name for a moment after a restart.
  for (int attempt = 0; attempt < 10; ++attempt) {
    if (bind(srv, reinterpret_cast<struct sockaddr *>(&addr), alen) == 0) break;
    if (attempt == 9) {
      LOGE("control: bind(@teesim) failed: %s", strerror(errno));
      close(srv);
      return nullptr;
    }
    sleep(1);
  }
  if (listen(srv, 4) != 0) {
    LOGE("control: listen() failed: %s", strerror(errno));
    close(srv);
    return nullptr;
  }
  LOGI("control: listening on @%s (hook=%s)", kSocketName, teesim_hook_name());

  for (;;) {
    int fd = accept(srv, nullptr, nullptr);
    if (fd < 0) {
      if (errno == EINTR) continue;
      LOGE("control: accept() failed: %s", strerror(errno));
      break;
    }
    HandleConnection(fd);  // one connection at a time; the daemon is the sole client
  }
  close(srv);
  return nullptr;
}

}  // namespace

extern "C" int teesim_android_api(void) { return AndroidApi(); }

extern "C" void teesim_control_start(void) {
  static bool started = false;
  if (started) return;
  started = true;
  pthread_t t;
  if (pthread_create(&t, nullptr, ServerThread, nullptr) == 0) {
    pthread_detach(t);
  } else {
    LOGE("control: pthread_create failed");
    started = false;
  }
}
