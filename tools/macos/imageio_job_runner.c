/*
 * Disposable-VM job wrapper for the ImageIO harness.
 *
 * UTM's CLI forwards a guest process exit code but does not expose every
 * waitpid detail.  This wrapper preserves normal exit vs signal vs timeout,
 * applies process limits before exec, and copies a matching macOS crash report
 * to a deterministic private path for the host-side adapter to retrieve.
 */

#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <libproc.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ARTIFACT_DIR "/private/tmp/vulnhunt-imageio"
#define STDOUT_PATH ARTIFACT_DIR "/stdout.bin"
#define STDERR_PATH ARTIFACT_DIR "/stderr.bin"
#define CRASH_PATH ARTIFACT_DIR "/crash.log"
#define BUFFER_SIZE (1024U * 1024U)

struct options {
    const char *expected_input_sha256;
    uint64_t wall_seconds;
    uint64_t cpu_seconds;
    uint64_t max_memory_bytes;
    uint64_t max_output_bytes;
    uint64_t max_open_files;
    const char *canary_interposer;
    const char *canary_interposer_sha256;
    uint64_t canary_value;
    uint64_t canary_minimum_allocation_bytes;
    uint64_t canary_maximum_allocation_bytes;
    bool canary_value_set;
    char **harness_argv;
};

static void usage(void) {
    fprintf(stderr,
            "usage: imageio-job-runner --expected-input-sha256 SHA256 "
            "--wall-time-seconds N --cpu-time-seconds N "
            "--max-process-memory-bytes N --max-output-bytes N "
            "--max-open-files N [--canary-interposer PATH "
            "--canary-interposer-sha256 SHA256 --canary-value BYTE "
            "--canary-minimum-allocation-bytes N "
            "--canary-maximum-allocation-bytes N] -- HARNESS ARGS...\n");
}

static bool parse_u64(const char *value, uint64_t *result) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0) {
        return false;
    }
    *result = (uint64_t)parsed;
    return true;
}

static bool parse_u8(const char *value, uint64_t *result) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > 255) {
        return false;
    }
    *result = (uint64_t)parsed;
    return true;
}

static bool valid_sha256(const char *value) {
    static const char prefix[] = "sha256:";
    if (strncmp(value, prefix, sizeof(prefix) - 1) != 0 || strlen(value) != 71) {
        return false;
    }
    for (size_t i = sizeof(prefix) - 1; i < 71; ++i) {
        char c = value[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool parse_options(int argc, char **argv, struct options *options) {
    memset(options, 0, sizeof(*options));
    int index = 1;
    while (index < argc && strcmp(argv[index], "--") != 0) {
        if (index + 1 >= argc) {
            return false;
        }
        const char *key = argv[index];
        const char *value = argv[index + 1];
        if (strcmp(key, "--expected-input-sha256") == 0 &&
            options->expected_input_sha256 == NULL) {
            options->expected_input_sha256 = value;
        } else if (strcmp(key, "--wall-time-seconds") == 0 &&
                   options->wall_seconds == 0) {
            if (!parse_u64(value, &options->wall_seconds)) return false;
        } else if (strcmp(key, "--cpu-time-seconds") == 0 &&
                   options->cpu_seconds == 0) {
            if (!parse_u64(value, &options->cpu_seconds)) return false;
        } else if (strcmp(key, "--max-process-memory-bytes") == 0 &&
                   options->max_memory_bytes == 0) {
            if (!parse_u64(value, &options->max_memory_bytes)) return false;
        } else if (strcmp(key, "--max-output-bytes") == 0 &&
                   options->max_output_bytes == 0) {
            if (!parse_u64(value, &options->max_output_bytes)) return false;
        } else if (strcmp(key, "--max-open-files") == 0 &&
                   options->max_open_files == 0) {
            if (!parse_u64(value, &options->max_open_files)) return false;
        } else if (strcmp(key, "--canary-interposer") == 0 &&
                   options->canary_interposer == NULL) {
            options->canary_interposer = value;
        } else if (strcmp(key, "--canary-interposer-sha256") == 0 &&
                   options->canary_interposer_sha256 == NULL) {
            options->canary_interposer_sha256 = value;
        } else if (strcmp(key, "--canary-value") == 0 &&
                   !options->canary_value_set) {
            if (!parse_u8(value, &options->canary_value)) return false;
            options->canary_value_set = true;
        } else if (strcmp(key, "--canary-minimum-allocation-bytes") == 0 &&
                   options->canary_minimum_allocation_bytes == 0) {
            if (!parse_u64(value, &options->canary_minimum_allocation_bytes)) return false;
        } else if (strcmp(key, "--canary-maximum-allocation-bytes") == 0 &&
                   options->canary_maximum_allocation_bytes == 0) {
            if (!parse_u64(value, &options->canary_maximum_allocation_bytes)) return false;
        } else {
            return false;
        }
        index += 2;
    }
    if (index >= argc || strcmp(argv[index], "--") != 0 || index + 1 >= argc) {
        return false;
    }
    options->harness_argv = &argv[index + 1];
    bool any_canary = options->canary_interposer != NULL ||
                      options->canary_interposer_sha256 != NULL ||
                      options->canary_value_set ||
                      options->canary_minimum_allocation_bytes > 0 ||
                      options->canary_maximum_allocation_bytes > 0;
    bool complete_canary = options->canary_interposer != NULL &&
                           options->canary_interposer_sha256 != NULL &&
                           valid_sha256(options->canary_interposer_sha256) &&
                           options->canary_value_set &&
                           options->canary_minimum_allocation_bytes > 0 &&
                           options->canary_minimum_allocation_bytes <=
                               options->canary_maximum_allocation_bytes;
    return options->expected_input_sha256 != NULL &&
           valid_sha256(options->expected_input_sha256) &&
           options->wall_seconds > 0 && options->cpu_seconds > 0 &&
           options->cpu_seconds <= options->wall_seconds &&
           options->max_memory_bytes > 0 && options->max_output_bytes > 0 &&
           options->max_open_files > 0 && (!any_canary || complete_canary);
}

static const char *find_harness_input(char **argv) {
    for (size_t i = 0; argv[i] != NULL; ++i) {
        if (strcmp(argv[i], "--input") == 0 && argv[i + 1] != NULL) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static bool sha256_file(const char *path, char output[72]) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        close(fd);
        return false;
    }
    bool ok = true;
    for (;;) {
        ssize_t count = read(fd, buffer, BUFFER_SIZE);
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        CC_SHA256_Update(&context, buffer, (CC_LONG)count);
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    if (ok) CC_SHA256_Final(digest, &context);
    free(buffer);
    close(fd);
    if (!ok) return false;
    memcpy(output, "sha256:", 7);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        snprintf(output + 7 + i * 2, 3, "%02x", digest[i]);
    }
    output[71] = '\0';
    return true;
}

static void sha256_argv(char **argv, char output[72]) {
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    for (size_t i = 0; argv[i] != NULL; ++i) {
        CC_SHA256_Update(&context, argv[i], (CC_LONG)strlen(argv[i]));
        const unsigned char separator = 0;
        CC_SHA256_Update(&context, &separator, 1);
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    memcpy(output, "sha256:", 7);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        snprintf(output + 7 + i * 2, 3, "%02x", digest[i]);
    }
    output[71] = '\0';
}

static bool set_one_limit(int resource, uint64_t value, const char *label) {
    struct rlimit limit = {.rlim_cur = (rlim_t)value, .rlim_max = (rlim_t)value};
    if (setrlimit(resource, &limit) == 0) return true;
    dprintf(STDERR_FILENO, "failed to apply %s resource limit: %s\n",
            label, strerror(errno));
    return false;
}

static int open_artifact(const char *path) {
    unlink(path);
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000U + (uint64_t)value.tv_nsec / 1000000U;
}

static bool has_crash_suffix(const char *name) {
    size_t length = strlen(name);
    return (length > 4 && strcmp(name + length - 4, ".ips") == 0) ||
           (length > 6 && strcmp(name + length - 6, ".crash") == 0);
}

static bool copy_file_bounded(const char *source, const char *target,
                              uint64_t maximum, bool *truncated) {
    struct stat metadata;
    if (stat(source, &metadata) != 0 || metadata.st_size < 0) return false;
    if ((uint64_t)metadata.st_size > maximum) {
        *truncated = true;
        return false;
    }
    int input = open(source, O_RDONLY | O_NOFOLLOW);
    int output = open_artifact(target);
    if (input < 0 || output < 0) {
        if (input >= 0) close(input);
        if (output >= 0) close(output);
        return false;
    }
    char buffer[64 * 1024];
    bool ok = true;
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(output, buffer + offset, (size_t)(count - offset));
            if (written < 0) {
                if (errno == EINTR) continue;
                ok = false;
                break;
            }
            offset += written;
        }
        if (!ok) break;
    }
    close(input);
    close(output);
    if (!ok) unlink(target);
    return ok;
}

static bool copy_newest_crash(const char *executable, time_t started_at,
                              uint64_t maximum, bool *truncated) {
    const char *base = strrchr(executable, '/');
    base = base == NULL ? executable : base + 1;
    struct passwd *account = getpwuid(getuid());
    if (account == NULL) return false;
    char directory_path[PATH_MAX];
    if (snprintf(directory_path, sizeof(directory_path),
                 "%s/Library/Logs/DiagnosticReports", account->pw_dir) >=
        (int)sizeof(directory_path)) {
        return false;
    }

    DIR *directory = opendir(directory_path);
    if (directory == NULL) return false;
    char selected[PATH_MAX] = {0};
    time_t selected_time = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, base, strlen(base)) != 0 ||
            !has_crash_suffix(entry->d_name)) {
            continue;
        }
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", directory_path,
                     entry->d_name) >= (int)sizeof(candidate)) {
            continue;
        }
        struct stat metadata;
        if (lstat(candidate, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            metadata.st_mtime < started_at || metadata.st_mtime < selected_time) {
            continue;
        }
        selected_time = metadata.st_mtime;
        strlcpy(selected, candidate, sizeof(selected));
    }
    closedir(directory);
    if (selected[0] == '\0') return false;
    return copy_file_bounded(selected, CRASH_PATH, maximum, truncated);
}

static bool wait_for_crash(const char *executable, time_t started_at,
                           uint64_t maximum, bool *truncated) {
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (copy_newest_crash(executable, started_at, maximum, truncated)) {
            return true;
        }
        if (*truncated) return false;
        usleep(100000);
    }
    return false;
}

int main(int argc, char **argv) {
    struct options options;
    if (!parse_options(argc, argv, &options)) {
        usage();
        return 64;
    }
    const char *input_path = find_harness_input(options.harness_argv);
    if (input_path == NULL) {
        fprintf(stderr, "harness argv does not contain --input\n");
        return 64;
    }

    char input_sha256[72];
    if (!sha256_file(input_path, input_sha256)) {
        fprintf(stderr, "cannot hash guest input\n");
        return 66;
    }
    if (strcmp(input_sha256, options.expected_input_sha256) != 0) {
        fprintf(stderr, "guest input digest mismatch\n");
        return 65;
    }
    char canary_sha256[72] = {0};
    if (options.canary_interposer != NULL) {
        if (!sha256_file(options.canary_interposer, canary_sha256) ||
            strcmp(canary_sha256, options.canary_interposer_sha256) != 0) {
            fprintf(stderr, "canary interposer digest mismatch\n");
            return 65;
        }
    }
    char argv_sha256[72];
    sha256_argv(options.harness_argv, argv_sha256);

    if (mkdir(ARTIFACT_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "cannot create private artifact directory\n");
        return 73;
    }
    unlink(CRASH_PATH);
    int stdout_fd = open_artifact(STDOUT_PATH);
    int stderr_fd = open_artifact(STDERR_PATH);
    if (stdout_fd < 0 || stderr_fd < 0) {
        fprintf(stderr, "cannot create private output files\n");
        if (stdout_fd >= 0) close(stdout_fd);
        if (stderr_fd >= 0) close(stderr_fd);
        return 73;
    }

    time_t started_at = time(NULL);
    uint64_t started_ms = monotonic_milliseconds();
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "cannot fork harness process\n");
        close(stdout_fd);
        close(stderr_fd);
        return 71;
    }
    if (child == 0) {
        if (dup2(stdout_fd, STDOUT_FILENO) < 0 ||
            dup2(stderr_fd, STDERR_FILENO) < 0) {
            _exit(71);
        }
        close(stdout_fd);
        close(stderr_fd);
        if (!set_one_limit(RLIMIT_CPU, options.cpu_seconds, "CPU") ||
            !set_one_limit(RLIMIT_NOFILE, options.max_open_files, "open files") ||
            !set_one_limit(RLIMIT_FSIZE, options.max_output_bytes, "file size")) {
            _exit(71);
        }
        if (options.canary_interposer != NULL) {
            char byte_value[4];
            char minimum[32];
            char maximum[32];
            snprintf(byte_value, sizeof(byte_value), "%llu",
                     (unsigned long long)options.canary_value);
            snprintf(minimum, sizeof(minimum), "%llu",
                     (unsigned long long)options.canary_minimum_allocation_bytes);
            snprintf(maximum, sizeof(maximum), "%llu",
                     (unsigned long long)options.canary_maximum_allocation_bytes);
            if (setenv("DYLD_INSERT_LIBRARIES", options.canary_interposer, 1) != 0 ||
                setenv("VULNHUNT_CANARY_BYTE", byte_value, 1) != 0 ||
                setenv("VULNHUNT_CANARY_MIN_BYTES", minimum, 1) != 0 ||
                setenv("VULNHUNT_CANARY_MAX_BYTES", maximum, 1) != 0 ||
                setenv("VULNHUNT_CANARY_REVISION", "m16-canary-interposer-v1", 1) != 0) {
                _exit(71);
            }
        }
        execv(options.harness_argv[0], options.harness_argv);
        dprintf(STDERR_FILENO, "failed to exec harness: %s\n", strerror(errno));
        _exit(71);
    }
    close(stdout_fd);
    close(stderr_fd);

    int status = 0;
    bool timed_out = false;
    bool memory_limit_exceeded = false;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0) {
            if (errno == EINTR) continue;
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            break;
        }
        if (monotonic_milliseconds() - started_ms >= options.wall_seconds * 1000U) {
            timed_out = true;
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        struct rusage_info_v4 usage;
        if (proc_pid_rusage(child, RUSAGE_INFO_V4, (rusage_info_t *)&usage) == 0 &&
            usage.ri_phys_footprint > options.max_memory_bytes) {
            memory_limit_exceeded = true;
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        usleep(10000);
    }

    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int signal_code = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    bool crash_present = false;
    bool crash_truncated = false;
    if (signal_code != 0 && !timed_out && !memory_limit_exceeded) {
        crash_present = wait_for_crash(options.harness_argv[0], started_at,
                                       options.max_output_bytes, &crash_truncated);
    }
    uint64_t duration_ms = monotonic_milliseconds() - started_ms;

    printf("{");
    printf("\"schema_version\":\"imageio-job-result-v1\",");
    printf("\"input_sha256\":\"%s\",", input_sha256);
    printf("\"argv_sha256\":\"%s\",", argv_sha256);
    if (exit_code >= 0) printf("\"exit_code\":%d,", exit_code);
    else printf("\"exit_code\":null,");
    if (signal_code > 0) printf("\"terminating_signal\":%d,", signal_code);
    else printf("\"terminating_signal\":null,");
    printf("\"timed_out\":%s,", timed_out ? "true" : "false");
    printf("\"memory_limit_exceeded\":%s,",
           memory_limit_exceeded ? "true" : "false");
    printf("\"duration_ms\":%llu,", (unsigned long long)duration_ms);
    printf("\"crash_log_present\":%s,", crash_present ? "true" : "false");
    printf("\"crash_log_truncated\":%s,", crash_truncated ? "true" : "false");
    if (options.canary_interposer != NULL) {
        printf("\"canary_interposer_sha256\":\"%s\",", canary_sha256);
        printf("\"canary_value\":%llu,", (unsigned long long)options.canary_value);
    } else {
        printf("\"canary_interposer_sha256\":null,");
        printf("\"canary_value\":null,");
    }
    printf("\"wall_time_seconds\":%llu,", (unsigned long long)options.wall_seconds);
    printf("\"cpu_time_seconds\":%llu,", (unsigned long long)options.cpu_seconds);
    printf("\"max_process_memory_bytes\":%llu,",
           (unsigned long long)options.max_memory_bytes);
    printf("\"max_output_bytes\":%llu,", (unsigned long long)options.max_output_bytes);
    printf("\"max_open_files\":%llu", (unsigned long long)options.max_open_files);
    printf("}\n");
    return 0;
}
