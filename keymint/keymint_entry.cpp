// Injection entry point for the KeyMint interceptor.
//
// The injector loads this library into keystore2 and calls entry(). We read the
// keybox and target list from the module configuration, build the TA, and install
// the AIBinder_transact hook. If the keybox is missing we install nothing, so a
// misconfigured module is a no-op rather than a hazard.

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "logging.hpp"

extern "C" bool teesim_router_init(const char* keybox_xml, size_t len);
extern "C" void teesim_router_configure(bool target_all, const char* const* pkgs, int n);
extern "C" bool teesim_hook_install();

namespace {

// keystore2 runs unprivileged, so these paths must be readable by it; the module
// is responsible for placing the configuration where keystore2 can reach it.
constexpr const char* kKeyboxPath = "/data/adb/teesim/keybox.xml";
constexpr const char* kTargetPath = "/data/adb/teesim/target.txt";

std::string ReadFile(const char* path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Extract package names from target.txt, ignoring comments, blank lines, keybox
// selectors ("[file.xml]") and any trailing mode suffix ('!' or '?').
std::vector<std::string> ParseTargets(const std::string& text) {
  std::vector<std::string> out;
  std::stringstream ss(text);
  std::string line;
  while (std::getline(ss, line)) {
    // Trim whitespace.
    size_t b = line.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) continue;
    size_t e = line.find_last_not_of(" \t\r\n");
    line = line.substr(b, e - b + 1);
    if (line.empty() || line[0] == '#' || line[0] == '[') continue;
    if (line.back() == '!' || line.back() == '?') line.pop_back();
    if (!line.empty()) out.push_back(line);
  }
  return out;
}

}  // namespace

extern "C" [[gnu::visibility("default")]] bool entry(void* /*handle*/) {
  LOGI("TEESimulator KeyMint interceptor loading");

  std::string keybox = ReadFile(kKeyboxPath);
  if (keybox.empty()) {
    LOGE("No keybox at %s; not installing interceptor", kKeyboxPath);
    return false;
  }
  if (!teesim_router_init(keybox.c_str(), keybox.size())) {
    LOGE("TA init failed (bad keybox?)");
    return false;
  }

  std::vector<std::string> targets = ParseTargets(ReadFile(kTargetPath));
  std::vector<const char*> ptrs;
  ptrs.reserve(targets.size());
  for (const auto& t : targets) ptrs.push_back(t.c_str());
  teesim_router_configure(false, ptrs.data(), static_cast<int>(ptrs.size()));

  bool ok = teesim_hook_install();
  LOGI("TEESimulator KeyMint interceptor installed=%d targets=%zu", ok, targets.size());
  return ok;
}
