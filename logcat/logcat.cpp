// In-process log reader for the control daemon.
//
// The daemon used to tail logs by spawning a `logcat` child and reading its stdout in Kotlin, with a
// filterspec of `TEESimulator:V *:I`. That pulls the WHOLE device log stream through a pipe and
// regex-filters it in the JVM, so any flood — e.g. the KeyAdmin accept loop in #265 — was carried at
// full volume into the daemon and amplified by the reader that was meant to observe it.
//
// This replaces that with the platform's own log-reader API (liblog), the same one `logcat` uses,
// running on one daemon thread: it reads logd directly, filters in C to only the lines we keep, and
// serves them two ways — a bounded in-memory ring the WebUI polls incrementally (nativePoll), and a
// set of rotating files on disk so a crash's context survives a restart and can be downloaded whole.
//
// It deliberately does NOT re-capture its own output: the reader emits nothing under the daemon's
// "TEESimulator" tag (its own status lines go straight into the log file, never back through logd), so
// there is no feedback path for it to spin on. The liblog reader symbols are absent from the NDK stub;
// they are declared in logcat.h and resolved at runtime against the device's real liblog.so
// (-Wl,-z,undefs), so nothing here is device-specific.

#include "logcat.h"

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace {

// Standard logcat priority characters, indexed by android_LogPriority.
constexpr std::array<char, ANDROID_LOG_SILENT + 1> kLogChar = {
    /*UNKNOWN*/ 'I', /*DEFAULT*/ 'I', /*VERBOSE*/ 'V', /*DEBUG*/ 'D', /*INFO*/ 'I',
    /*WARN*/ 'W',    /*ERROR*/ 'E',   /*FATAL*/ 'F',    /*SILENT*/ 'I',
};

// Tags we always keep, whatever the pid: the daemon, the TA and both native interceptors all log under
// "TEESimulator"; "AndroidRuntime" carries Java crash reports. A native abort (priority FATAL) and the
// crash buffer are kept regardless of tag.
constexpr auto kKeepTags = std::array{"AndroidRuntime"sv, "TEESimulator"sv};

// One field separator the WebUI parse splits on. Neither a tag nor a log message contains it.
constexpr char kSep = '\x01';

// Ring capacity (lines) the WebUI polls; matches the client's own retention cap.
constexpr size_t kRingCap = 4000;

// On-disk rotation: teesim.log plus up to kMaxParts rolled parts, each capped at kMaxLogSize.
constexpr size_t kMaxLogSize = 2 * 1024 * 1024;  // 2 MB per part
constexpr int kMaxParts = 4;                     // teesim.log + .1..4  => ~10 MB of history
constexpr long kLogBufferSize = 256 * 1024;      // ask logd for a larger buffer to cut dropped reads

// The injected keystore/keystore2 pid (set from Kotlin by the Injector); -1 when none is live. Its
// lines are kept so the Logs panel shows what happens inside the process we hook, not only our own.
std::atomic<int> g_target_pid{-1};

struct Entry {
    uint64_t seq;
    char level;
    std::string tag;
    std::string text;  // the full threadtime-formatted line the Logs panel renders
};

// The ring the WebUI polls. Guarded by its own mutex; the single reader thread appends, the KeyAdmin
// handler threads read snapshots. seq is monotonic so a client cursor never needs resetting.
std::mutex g_ring_mu;
std::deque<Entry> g_ring;
uint64_t g_seq = 0;

void RingPush(char level, std::string_view tag, std::string_view text) {
    std::lock_guard<std::mutex> lk(g_ring_mu);
    if (g_ring.size() >= kRingCap) g_ring.pop_front();
    g_ring.push_back(Entry{++g_seq, level, std::string(tag), std::string(text)});
}

class Logcat {
public:
    Logcat(std::string dir, int64_t since_ms) : dir_(std::move(dir)), since_ms_(since_ms) {}
    [[noreturn]] void Run();

private:
    void OpenCurrent();
    void Rotate();
    void RotateIfNewBoot();
    void WriteLine(std::string_view line);
    void Emit(std::string_view line);  // status line straight to the file, never back through logd
    void Process(struct log_msg* buf);
    void OnCrash(int ret);

    std::string dir_;
    // Wall-clock ms at which the daemon started, passed in from Kotlin. The first attach asks logd
    // for everything since this instant — see Run().
    int64_t since_ms_;
    int fd_ = -1;
    size_t written_ = 0;
    pid_t my_pid_ = getpid();
    // The previous kept line's wall-clock second, for the clock-step detector in Process(). Persists
    // across a logd reconnect (OnCrash) — only a genuine boot marker resets what counts as expected.
    time_t last_sec_ = 0;
    bool have_last_sec_ = false;
    // Consecutive failed reads, and the run length that triggers the next `ctl.restart logd`. Reset
    // by Run() as soon as a reconnect delivers a line; see OnCrash.
    size_t crash_count_ = 0;
    size_t restart_wait_ = 8;
};

void Logcat::OpenCurrent() {
    std::string path = dir_ + "/teesim.log";
    // Append so a service.sh respawn keeps the previous run's tail; rotation still bounds the size.
    fd_ = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    written_ = 0;
    if (fd_ >= 0) {
        struct stat st{};
        if (fstat(fd_, &st) == 0) written_ = static_cast<size_t>(st.st_size);
    }
}

void Logcat::Rotate() {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    char oldp[PATH_MAX], newp[PATH_MAX];
    snprintf(oldp, sizeof(oldp), "%s/teesim.%d.log", dir_.c_str(), kMaxParts);
    unlink(oldp);  // drop the oldest part (ok if absent)
    for (int i = kMaxParts - 1; i >= 1; --i) {
        snprintf(oldp, sizeof(oldp), "%s/teesim.%d.log", dir_.c_str(), i);
        snprintf(newp, sizeof(newp), "%s/teesim.%d.log", dir_.c_str(), i + 1);
        rename(oldp, newp);  // ok if the source is absent
    }
    snprintf(oldp, sizeof(oldp), "%s/teesim.log", dir_.c_str());
    snprintf(newp, sizeof(newp), "%s/teesim.1.log", dir_.c_str());
    rename(oldp, newp);
    OpenCurrent();  // a fresh, empty teesim.log
}

// Give a reboot its own file boundary, without undoing the reason teesim.log always appends.
//
// Rotation is otherwise a byte-count decision (Rotate(), above); this adds a second trigger alongside
// it, so a boot boundary is always a file boundary too.
//
// The trigger has to tell a genuine reboot apart from a service.sh respawn within the same boot,
// because OpenCurrent's append-through-restart is deliberate: a crash loop's whole point is that its
// restarts belong in one file, next to each other, not scattered one-per-file. The kernel's boot id
// (/proc/sys/kernel/random/boot_id, a UUID regenerated once per kernel boot, world-readable, no
// special permission needed) is exactly the distinction this needs and nothing else on the device
// offers as cheaply: unlike a wall-clock timestamp it cannot be fooled by an unsynced RTC, and unlike
// comparing against the last line already in the file it costs one small read, not a parse.
//
// The last-seen id lives in a marker file next to the logs. A rotate fires whenever the current id
// does not match it, and a missing marker counts as a mismatch: a non-empty teesim.log with no
// marker (first run of a marker-writing build, or a reinstall that wiped the data directory) holds
// an earlier boot's lines and deserves the same boundary.
//
// What still holds a rotation back is written_ == 0: a brand-new, genuinely empty teesim.log has
// nothing worth preserving, so a fresh install's very first line does not burn a pointless rotation
// on a file with zero bytes in it. A boot_id read failure (sandboxed environment, odd kernel)
// degrades to always appending, since there is no signal to act on either way.
//
// Rotate()'s own file count is untouched by any of this: it always drops teesim.4.log and shifts the
// rest up by one, so the chain is teesim.log plus at most four rolled parts — five files, total, on
// disk under log/ — no matter how often a boot fires it. A device that reboots often just spends that
// fixed budget on more, shorter-lived boots rather than fewer, longer ones; it can never grow the
// file count past five.
void Logcat::RotateIfNewBoot() {
    std::string boot_id;
    {
        int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return;  // no signal either way; keep appending
        char buf[64];
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);
        if (n <= 0) return;
        boot_id.assign(buf, static_cast<size_t>(n));
        while (!boot_id.empty() && (boot_id.back() == '\n' || boot_id.back() == '\r')) {
            boot_id.pop_back();
        }
        if (boot_id.empty()) return;
    }

    const std::string marker_path = dir_ + "/.boot_id";
    std::string last;
    bool had_marker = false;
    {
        int fd = open(marker_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char buf[64];
            ssize_t n = read(fd, buf, sizeof(buf));
            close(fd);
            if (n > 0) {
                last.assign(buf, static_cast<size_t>(n));
                had_marker = true;
            }
        }
    }

    const bool new_boot = !had_marker || last != boot_id;

    int fd = open(marker_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        // Best effort. A persistent write failure here (full or read-only data partition) leaves
        // the marker stuck at an older id, so every later respawn within this SAME boot reads it as
        // a mismatch and rotates again — over-rotating rather than under-rotating. A partition in
        // that state has already broken the config and keybox persistence this daemon depends on.
        ssize_t unused = write(fd, boot_id.data(), boot_id.size());
        (void)unused;
        close(fd);
    }

    if (new_boot && written_ > 0) {
        Emit("\n--- new boot detected; rotating the previous boot's log ---");
        Rotate();
    }
}

void Logcat::WriteLine(std::string_view line) {
    if (fd_ < 0) return;
    bool add_nl = line.empty() || line.back() != '\n';
    struct iovec iov[2] = {{const_cast<char*>(line.data()), line.size()},
                           {const_cast<char*>("\n"), add_nl ? 1U : 0U}};
    ssize_t n = writev(fd_, iov, 2);
    if (n > 0) written_ += static_cast<size_t>(n);
    if (written_ >= kMaxLogSize) Rotate();
}

void Logcat::Emit(std::string_view line) {
    // The reader's own status (logd resets, rotation notes). Written to the file only — never through
    // __android_log so the reader can never observe and re-capture itself.
    WriteLine(line);
}

void Logcat::Process(struct log_msg* buf) {
    AndroidLogEntry entry;
    if (android_log_processLogBuffer(&buf->entry, &entry) < 0) return;

    // tagLen counts the trailing NUL (drop it); messageLen is the exact message length (no NUL). Strip
    // trailing newlines off the message so one liblog entry (a whole Java stack trace arrives as one)
    // is one ring line, not many blanks.
    std::string_view tag(entry.tag, entry.tagLen > 0 ? entry.tagLen - 1 : 0);
    std::string_view msg(entry.message, entry.messageLen);
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r')) msg.remove_suffix(1);

    int tpid = g_target_pid.load(std::memory_order_relaxed);
    // Kept means kept in full: whatever reaches this point is written to the ring and the file at
    // whatever level it arrived at. Level filtering happens once, at display time in the WebUI; a
    // cutoff here would silently hide lines the WebUI's "show everything" setting asks for.
    // The crash buffer is kept for crash REPORTS, which are never below WARN: a native abort and its
    // tombstone arrive as FATAL, and a Java "FATAL EXCEPTION" as ERROR under AndroidRuntime, which
    // the tag list already keeps whatever buffer it came in on. The floor matters because that buffer
    // is not reserved for crashes in practice — MediaTek vendor libraries stamp three INFO lines of
    // build ids into it from every process that loads one, which on a lagos device was ~3% of
    // everything captured, spending ring slots and log-file bytes on other processes' build metadata.
    bool keep = std::find(kKeepTags.begin(), kKeepTags.end(), tag) != kKeepTags.end() ||
                entry.priority == ANDROID_LOG_FATAL ||
                (buf->id() == LOG_ID_CRASH && entry.priority >= ANDROID_LOG_WARN) ||
                (tpid > 0 && entry.pid == tpid);
    if (!keep) return;

    char level = kLogChar[entry.priority <= ANDROID_LOG_SILENT ? entry.priority : ANDROID_LOG_INFO];

    // A boot whose clock has not synced yet logs the platform's no-RTC default date, then jumps
    // forward by years once NTP corrects it, inside the same boot. Two lines written a second apart
    // would then read as years apart, so a large jump between adjacent lines is marked.
    // RotateIfNewBoot cannot catch this: the boot id does not change mid-boot.
    //
    // A boot marker's own arrival is exempted, since the device really was off and that gap is
    // expected; a clock step deep inside one boot's startup is not near a marker and gets flagged. The threshold is generous enough that no ordinary idle stretch on a real device
    // trips it: something reaches this filtered stream far more often than every six hours on any
    // phone actually being used, so a gap that large is itself worth a line even in the rare case it
    // is not a clock step.
    constexpr time_t kClockGapWarnSec = 6 * 3600;
    const bool is_boot_marker = tag == "AndroidRuntime"sv && msg.find(">>>>>> START"sv) != msg.npos;
    if (have_last_sec_ && !is_boot_marker) {
        const long long delta =
            static_cast<long long>(entry.tv_sec) - static_cast<long long>(last_sec_);
        if (delta > kClockGapWarnSec || delta < -kClockGapWarnSec) {
            char m[160];
            snprintf(m, sizeof(m),
                    "\n--- wall-clock gap of %lldh between adjacent lines, no reboot in between "
                    "(device asleep, or the clock stepped) ---",
                    delta / 3600);
            Emit(m);
        }
    }
    last_sec_ = entry.tv_sec;
    have_last_sec_ = true;

    // threadtime layout: "MM-DD HH:MM:SS.mmm  PID  TID L TAG: message". Kept human-readable for the
    // file and the download; the WebUI reads level/tag from the packed fields, not by re-parsing this.
    struct tm tm_info;
    time_t sec = entry.tv_sec;
    localtime_r(&sec, &tm_info);
    char head[64];
    int hn = snprintf(head, sizeof(head), "%02d-%02d %02d:%02d:%02d.%03ld %5d %5d %c ",
                      tm_info.tm_mon + 1, tm_info.tm_mday, tm_info.tm_hour, tm_info.tm_min,
                      tm_info.tm_sec, entry.tv_nsec / 1000000, entry.pid, entry.tid, level);

    std::string line;
    line.reserve(hn + tag.size() + 2 + msg.size());
    line.append(head, hn);
    line.append(tag);
    line.append(": ");
    line.append(msg);

    WriteLine(line);
    RingPush(level, tag, line);
}

// `ret` is android_logger_list_read's own return value, not an errno: liblog returns a NEGATED errno
// on failure and 0 when logd closed the stream (its own restart, or device shutdown), and never
// touches the global errno. Reading errno here instead printed "Success" for every clean close, and
// for the rest whatever android_logger_list_free's close()/free() had left behind.
//
// Only a run of failures with no line read in between counts towards the restart: a logd that resets
// occasionally over a long uptime is not a logd that needs restarting, and restarting it discards the
// whole device's log buffer.
void Logcat::OnCrash(int ret) {
    if (++crash_count_ >= restart_wait_) {
        Emit("\n--- logd unreadable too many times; requesting a restart ---");
        __system_property_set("ctl.restart", "logd");
        if (restart_wait_ < 1024) restart_wait_ <<= 1; else crash_count_ = 0;
    } else {
        std::string m = "\n--- logd read failed (";
        m += ret == 0 ? "stream closed" : strerror(-ret);
        m += "); retrying in 1s ---";
        Emit(m);
    }
    std::this_thread::sleep_for(1s);
}

void Logcat::Run() {
    OpenCurrent();
    RotateIfNewBoot();
    // The first attach asks logd for a time WINDOW, not a line count, because neither count works.
    //
    // liblog passes `tail` straight to logd, where 0 means NO LIMIT: it dumps the opened buffers
    // whole before following, which is how plain `logcat` prints history. That dump costs the #265
    // flood this reader exists to avoid, and because teesim.log is opened O_APPEND so a service.sh
    // respawn continues the same file, it re-appends lines the previous run already wrote.
    //
    // "Follow from here" (tail = 1) loses the other end. The daemon logs its first line and then the
    // session header — module version, device, date, the three things that identify a log pasted
    // into an issue — before this thread reaches the read below, and once they are only in logd's
    // buffer nothing asks for them again. A start time is exactly the window that is ours:
    // everything since the daemon began, nothing from before it. Taken in Kotlin ahead of that
    // first line, so the race cannot be lost rather than merely being narrow.
    //
    // The anchor is only ever used for the first attach, moments after it was taken, so it cannot
    // name a time logd has already pruned past — which would turn a window back into a whole dump.
    // A reconnect pulls the last few lines instead, for context across a logd reset.
    bool attached = false;
    unsigned int tail = 1;  // fallback first attach, with no anchor: follow from here
    while (true) {
        struct logger_list* list;
        if (!attached && since_ms_ > 0) {
            struct log_time since = {static_cast<uint32_t>(since_ms_ / 1000),
                                     static_cast<uint32_t>((since_ms_ % 1000) * 1000000)};
            list = android_logger_list_alloc_time(0 /* blocking */, since, 0);
        } else {
            list = android_logger_list_alloc(0 /* blocking */, tail, 0);
        }
        if (!list) {
            OnCrash(-ENOMEM);  // the only way liblog fails to allocate a reader
            continue;          // still unattached: the next try keeps the anchor
        }
        attached = true;
        tail = 10;  // a reconnect after a logd reset: pull the last few lines back for context
        for (log_id_t id : {LOG_ID_MAIN, LOG_ID_SYSTEM, LOG_ID_CRASH}) {
            auto* logger = android_logger_open(list, id);
            if (logger && android_logger_get_log_size(logger) < kLogBufferSize) {
                android_logger_set_log_size(logger, kLogBufferSize);
            }
        }

        struct log_msg msg;
        int ret;
        while ((ret = android_logger_list_read(list, &msg)) > 0) {
            crash_count_ = 0;  // this connection is delivering; it is not part of a failure run
            // Never re-read our own reader identity. (We emit nothing through logd, so this only guards
            // against a future __android_log call from this pid slipping into the stream.)
            if (msg.entry.pid == static_cast<int32_t>(my_pid_)) {
                AndroidLogEntry peek;
                if (android_log_processLogBuffer(&msg.entry, &peek) >= 0) {
                    std::string_view t(peek.tag, peek.tagLen > 0 ? peek.tagLen - 1 : 0);
                    if (t == "TEESimLog"sv) continue;
                }
            }
            Process(&msg);
        }
        android_logger_list_free(list);
        OnCrash(ret);
    }
}

}  // namespace

extern "C" JNIEXPORT void JNICALL Java_org_matrix_teesim_LogTail_nativeRun(JNIEnv* env, jobject,
                                                                           jstring dir,
                                                                           jlong since_ms) {
    const char* d = env->GetStringUTFChars(dir, nullptr);
    std::string dir_s = d ? d : "/data/adb/teesim/log";
    if (d) env->ReleaseStringUTFChars(dir, d);
    // Blocks for the life of the daemon; runs on the dedicated Kotlin thread that called it.
    Logcat(dir_s, since_ms).Run();
}

extern "C" JNIEXPORT void JNICALL Java_org_matrix_teesim_LogTail_nativeSetTargetPid(JNIEnv*, jobject,
                                                                                    jint pid) {
    g_target_pid.store(pid, std::memory_order_relaxed);
}


// Current maximum sequence number, so the WebUI's cursor can advance even when a poll returns nothing.
extern "C" JNIEXPORT jlong JNICALL Java_org_matrix_teesim_LogTail_nativeMaxSeq(JNIEnv*, jobject) {
    std::lock_guard<std::mutex> lk(g_ring_mu);
    return static_cast<jlong>(g_seq);
}

// Ring lines with seq greater than `after`, up to `max`, each packed as
// "seq \x01 level \x01 tag \x01 text" for the Kotlin side to split. Returns them oldest-first.
extern "C" JNIEXPORT jobjectArray JNICALL Java_org_matrix_teesim_LogTail_nativePoll(JNIEnv* env,
                                                                                    jobject,
                                                                                    jlong after,
                                                                                    jint max) {
    std::vector<std::string> out;
    {
        std::lock_guard<std::mutex> lk(g_ring_mu);
        for (const auto& e : g_ring) {
            if (e.seq <= static_cast<uint64_t>(after)) continue;
            std::string s;
            s.reserve(e.tag.size() + e.text.size() + 24);
            s += std::to_string(e.seq);
            s += kSep;
            s += e.level;
            s += kSep;
            s += e.tag;
            s += kSep;
            s += e.text;
            out.push_back(std::move(s));
            if (static_cast<jint>(out.size()) >= max) break;
        }
    }
    jclass strClass = env->FindClass("java/lang/String");
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(out.size()), strClass, nullptr);
    for (jsize i = 0; i < static_cast<jsize>(out.size()); ++i) {
        jstring js = env->NewStringUTF(out[i].c_str());
        env->SetObjectArrayElement(arr, i, js);
        env->DeleteLocalRef(js);
    }
    return arr;
}
