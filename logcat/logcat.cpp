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
    explicit Logcat(std::string dir) : dir_(std::move(dir)) {}
    [[noreturn]] void Run();

private:
    void OpenCurrent();
    void Rotate();
    void WriteLine(std::string_view line);
    void Emit(std::string_view line);  // status line straight to the file, never back through logd
    void Process(struct log_msg* buf);
    void OnCrash(int err);

    std::string dir_;
    int fd_ = -1;
    size_t written_ = 0;
    pid_t my_pid_ = getpid();
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
    bool keep = std::find(kKeepTags.begin(), kKeepTags.end(), tag) != kKeepTags.end() ||
                entry.priority == ANDROID_LOG_FATAL || buf->id() == LOG_ID_CRASH ||
                (tpid > 0 && entry.pid == tpid);
    if (!keep) return;

    char level = kLogChar[entry.priority <= ANDROID_LOG_SILENT ? entry.priority : ANDROID_LOG_INFO];

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

void Logcat::OnCrash(int err) {
    static size_t crash_count = 0;
    static size_t restart_wait = 8;
    if (++crash_count >= restart_wait) {
        Emit("\n--- logd unreadable too many times; requesting a restart ---");
        __system_property_set("ctl.restart", "logd");
        if (restart_wait < 1024) restart_wait <<= 1; else crash_count = 0;
    } else {
        std::string m = "\n--- logd read failed (";
        m += strerror(err);
        m += "); retrying in 1s ---";
        Emit(m);
    }
    std::this_thread::sleep_for(1s);
}

void Logcat::Run() {
    OpenCurrent();
    unsigned int tail = 0;  // first attach: no history, just follow
    while (true) {
        auto* list = android_logger_list_alloc(0 /* blocking */, tail, 0);
        if (!list) {
            OnCrash(errno);
            continue;
        }
        // On a reconnect after a logd reset, pull the last few lines back for context.
        tail = 10;
        for (log_id_t id : {LOG_ID_MAIN, LOG_ID_SYSTEM, LOG_ID_CRASH}) {
            auto* logger = android_logger_open(list, id);
            if (logger && android_logger_get_log_size(logger) < kLogBufferSize) {
                android_logger_set_log_size(logger, kLogBufferSize);
            }
        }

        struct log_msg msg;
        while (android_logger_list_read(list, &msg) > 0) {
            // Never re-read our own reader identity. (We emit nothing through logd, so this only guards
            // against a future __android_log call from this pid slipping into the stream.)
            if (msg.entry.pid == static_cast<uint32_t>(my_pid_)) {
                AndroidLogEntry peek;
                if (android_log_processLogBuffer(&msg.entry, &peek) >= 0) {
                    std::string_view t(peek.tag, peek.tagLen > 0 ? peek.tagLen - 1 : 0);
                    if (t == "TEESimLog"sv) continue;
                }
            }
            Process(&msg);
        }
        android_logger_list_free(list);
        OnCrash(errno);
    }
}

}  // namespace

extern "C" JNIEXPORT void JNICALL Java_org_matrix_teesim_LogTail_nativeRun(JNIEnv* env, jobject,
                                                                           jstring dir) {
    const char* d = env->GetStringUTFChars(dir, nullptr);
    std::string dir_s = d ? d : "/data/adb/teesim/log";
    if (d) env->ReleaseStringUTFChars(dir, d);
    // Blocks for the life of the daemon; runs on the dedicated Kotlin thread that called it.
    Logcat(dir_s).Run();
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
