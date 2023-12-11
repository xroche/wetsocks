/**
 * Wet Socks, leaky sockets reporter.
 * Thanks to Algolia for giving me the opportunity to develop this tools!
 * @maintainer Xavier Roche (xavier dot roche at algolia.com)
 */

#include <array>
#include <cassert>
#include <charconv>
#include <chrono>
#include <dlfcn.h>
#include <execinfo.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>

using namespace std::chrono_literals;

// Dump every (override with environment variable: WETSOCKS_DUMP_EVERY_S)
std::chrono::steady_clock::duration dumpEvery = 5min;

// Youngest socket to be considered leaking (override with environment variable: WETSOCKS_YOUNGEST_ENTRY_S)
std::chrono::steady_clock::duration youngestEntry = 30min;

// Grace for process to stabilize at startup (override with environment variable: WETSOCKS_WARMUP_ENTRY_S)
std::chrono::steady_clock::duration warmupEntry = 5min;

// Dump file prefix (override with environment variable: WETSOCKS_DUMP_FILE_PREFIX)
std::string dumpFilePrefix = "leaky-socket-stats-for-pid-";

// Silent (override with environment variable: WETSOCKS_SILENT=1)
bool silent = false;

#define EXPORTED __attribute__((visibility("default")))

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage
#define assertm(exp, msg) assert(((void)(msg), (exp)))
namespace {

/* Settings */
class StaticInit
{
public:
    StaticInit()
    {
        const auto mapEnvironmentTo = [](const char* name, auto& dest) {
            using Dest = std::decay_t<decltype(dest)>;
            if (char* s = std::getenv(name); s != nullptr && *s != '\0') {
                const std::string_view sv{ s };
                if constexpr (std::is_same_v<Dest, std::chrono::steady_clock::duration>) {
                    long d;
                    if (auto [ptr, err] = std::from_chars(sv.begin(), sv.end(), d); ptr == sv.end()) {
                        dest = std::chrono::seconds(d);
                        if (not silent) {
                            std::cerr << name << "=" << d << "s" << std::endl;
                        }
                    }
                } else if constexpr (std::is_same_v<Dest, std::string>) {
                    dest = std::string{ s };
                    if (not silent) {
                        std::cerr << name << "=" << sv << "s" << std::endl;
                    }
                } else if constexpr (std::is_same_v<Dest, bool>) {
                    dest = sv == "1" or sv == "true" or sv == "yes";
                    if (not silent) {
                        std::cerr << name << "=" << sv << "s" << std::endl;
                    }
                }
            }
        };
        mapEnvironmentTo("WETSOCKS_SILENT", silent);
        mapEnvironmentTo("WETSOCKS_DUMP_EVERY_S", dumpEvery);
        mapEnvironmentTo("WETSOCKS_YOUNGEST_ENTRY_S", youngestEntry);
        mapEnvironmentTo("WETSOCKS_WARMUP_ENTRY_S", warmupEntry);
        mapEnvironmentTo("WETSOCKS_DUMP_FILE_PREFIX", dumpFilePrefix);
    }
    ~StaticInit() {}
} staticInit;

/* Helper: get a glibc symbol */
template<typename F>
auto get_libc(const char* const name)
{
    auto* ptr = dlsym(RTLD_NEXT, name);
    assertm(ptr != nullptr, "Unable to find libc symbol");
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<F>(ptr);
}

/* Helper: get a glibc symbol once */
template<typename F>
auto get_libc_static(const char* const name)
{
    static const auto fun = get_libc<F>(name);
    return fun;
}

/* Helper: forward a function call */
template<typename F, typename... Ts>
auto forward_libc_function(F function, Ts... args)
{
    return function(args...);
}

/* Helper: take an original function from glibc, and forward it with slow/big
 * threshold checks */
template<typename F, typename... Ts>
auto forward_libc_size(const char* const name, Ts... args)
{
    const auto fun = get_libc_static<F>(name);
    return forward_libc_function(fun, args...);
}

/* Helper: take an original function from glibc, and forward it with slow
 * threshold checks */
template<typename F, typename... Ts>
auto forward_libc(const char* const name, Ts... args)
{
    return forward_libc_size<F, Ts...>(name, args...);
}

using Fd = int;
using Hash = std::size_t;

struct Backtrace
{
    static constexpr size_t capacity = 64;
    std::array<void*, capacity> traces{};
    int size{ 0 };
    Hash hash{ 0 };
};

struct SocketEntry
{
    std::chrono::steady_clock::time_point created{};
    Backtrace bt{};
};

void setBacktraceHash(Backtrace& bt)
{
    // FNV1a-like
    constexpr Hash prime = 0x100000001b3;
    constexpr Hash offset = 0xcbf29ce484222325;
    Hash hash{ offset };
    for (int i = 0; i < bt.size; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        hash ^= reinterpret_cast<uintptr_t>(bt.traces[i]);
        hash *= prime;
    }
    bt.hash = hash;
}

Backtrace getBacktrace()
{
    Backtrace bt{};
    const auto nbTraces = backtrace(bt.traces.data(), bt.traces.size());
    bt.size = nbTraces;
    setBacktraceHash(bt);
    return bt;
}

std::string_view getBacktraceString(const Backtrace& bt)
{
    // Resolving is costly; only do it once
    static std::unordered_map<Hash, std::string> cache{};

    if (auto entry = cache.find(bt.hash); entry != cache.end()) {
        return entry->second;
    }

    std::string s{};
    std::unique_ptr<char*, decltype(&std::free)> traces{ backtrace_symbols(bt.traces.data(), bt.size), std::free };
    for (int i = 0; i < bt.size; i++) {
        s.append(traces.get()[i]);
        s.append("\n");
    }
    const auto entry = cache.emplace(bt.hash, std::move(s));
    return entry.first->second;
}

const std::chrono::steady_clock::time_point oldestEntry{ std::chrono::steady_clock::now() + warmupEntry };

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::mutex lock{};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::chrono::steady_clock::time_point last{ std::chrono::steady_clock::now() };
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::unordered_map<Fd, SocketEntry> sockets{};

// NOLINTNEXTLINE(readability-function-size)
void dumpStats()
{
    const auto now = std::chrono::steady_clock::now();

    // Potentially leaking socket ?
    constexpr auto potentiallyLeaking = [&](const auto& info, const auto& elapsed) {
        return elapsed >= youngestEntry and info.created > oldestEntry;
    };

    // Collect unique backtraces
    struct UniqueBt
    {
        const SocketEntry* entry{ nullptr };
        size_t count{ 0 };
    };
    std::size_t nbPotentiallyLeaking{ 0 };
    std::unordered_map<std::size_t, UniqueBt> btList{};
    {
        for (const auto& [fd, info] : sockets) {
            const auto elapsed = now - info.created;
            if (not potentiallyLeaking(info, elapsed)) {
                continue;
            }
            nbPotentiallyLeaking++;

            if (auto pos = btList.find(info.bt.hash); pos != btList.end()) {
                pos->second.count++;
            } else {
                btList[info.bt.hash] = UniqueBt{ &info, 1 };
            }
        }
    }

    // Write stats
    std::ofstream file{ dumpFilePrefix + std::to_string(getpid()) + std::string{ ".txt" } };
    if (file) {
        file << "Summary of " << nbPotentiallyLeaking << " sockets still alive among " << sockets.size()
             << " due to " << std::to_string(btList.size()) << " actors:" << std::endl;

        file << "FD"
             << "\t"
             << "Elapsed"
             << "\t"
             << "Backtrace #" << std::endl;

        for (const auto& [fd, info] : sockets) {
            const auto elapsed = now - info.created;
            if (not potentiallyLeaking(info, elapsed)) {
                continue;
            }
            const auto elapsedS = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

            file << std::to_string(fd) << "\t" << std::to_string(elapsedS) << "s"
                 << "\t#" << std::to_string(info.bt.hash) << std::endl;
        }
        file << std::endl;

        for (const auto& [hash, info] : btList) {
            const auto resolved = getBacktraceString(info.entry->bt);
            file << "Backtrace #" << std::to_string(hash) << " (" << std::to_string(info.count) << " entries)"
                 << std::endl
                 << resolved << std::endl;
        }

        file.close();
    }
}

void recordNewSocket(Fd fd)
{
    if (fd == -1) {
        return;
    }

    std::scoped_lock scoped{ lock };
    sockets[fd] = SocketEntry{ std::chrono::steady_clock::now(), getBacktrace() };

    const auto now = std::chrono::steady_clock::now();
    if (now - last > dumpEvery) {
        last = now;
        dumpStats();
    }
}

}; // namespace

// Exported strong symbols.
extern "C"
{
    // Forward glibc declarations to be able to call them.

    EXPORTED extern int socket(int domain, int type, int protocol);
    int socket(int domain, int type, int protocol)
    {
        const int fd = forward_libc<decltype(socket)*>("socket", domain, type, protocol);
        recordNewSocket(fd);
        return fd;
    }

    // NOLINTNEXTLINE(readability-identifier-naming)
    EXPORTED extern int socketpair(int domain, int type, int protocol, int socket_vector[2]);
    // NOLINTNEXTLINE(readability-identifier-naming)
    int socketpair(int domain, int type, int protocol, int socket_vector[2])
    {
        const int result =
            forward_libc<decltype(socketpair)*>("socketpair", domain, type, protocol, socket_vector);
        if (result == 0) {
            recordNewSocket(socket_vector[0]);
            recordNewSocket(socket_vector[1]);
        }
        return result;
    }

    // NOLINTNEXTLINE(readability-redundant-declaration)
    EXPORTED extern int close(int fd);
    int close(int fd)
    {
        const int result = forward_libc<decltype(close)*>("close", fd);
        std::scoped_lock scoped{ lock };
        sockets.erase(fd);
        return result;
    }

    EXPORTED extern int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
    int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
    {
        const int fd = forward_libc<decltype(accept)*>("accept", sockfd, addr, addrlen);
        recordNewSocket(fd);
        return fd;
    }

    EXPORTED extern int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);
    int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags)
    {
        const int fd = forward_libc<decltype(accept4)*>("accept4", sockfd, addr, addrlen, flags);
        recordNewSocket(fd);
        return fd;
    }
};
