// QA only: deterministic libsystemd journal boundary; Qt, processor and real
// AF_UNIX/SOCK_SEQPACKET serialization run unchanged inside a private container.
#include <systemd/sd-journal.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int position = 0, field = 0, count = 0, descriptor = -1;
static std::vector<std::string> entries;
static bool fault(const char *value) {
    const char *actual = std::getenv("QA_JOURNAL_FAULT");
    return actual && std::strcmp(actual, value) == 0;
}
extern "C" {
int sd_journal_open(sd_journal **out, int) {
    if (fault("open")) { *out = nullptr; return -EACCES; }
    *out = reinterpret_cast<sd_journal *>(1);
    count = std::atoi(std::getenv("QA_JOURNAL_COUNT") ?: "0");
    descriptor = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    return 0;
}
void sd_journal_close(sd_journal *) { if(descriptor >= 0) close(descriptor); }
void sd_journal_flush_matches(sd_journal *) {}
int sd_journal_add_match(sd_journal *, const void *, size_t) { return fault("match") ? -EACCES : 0; }
int sd_journal_get_fd(sd_journal *) { return fault("fd") ? -EIO : descriptor; }
int sd_journal_process(sd_journal *) { return SD_JOURNAL_APPEND; }
int sd_journal_seek_head(sd_journal *) { position = 0; return fault("seek") ? -EIO : 0; }
int sd_journal_next(sd_journal *) {
    if (fault("read")) return -EIO;
    if (position >= count) return 0;
    ++position;
    const bool missing = std::getenv("QA_MISSING_CORES") && position % 2 == 0;
    entries = {"SYSLOG_IDENTIFIER=systemd-coredump", "COREDUMP_UID=1000",
        "COREDUMP_PID=" + std::to_string(10000 + position),
        "COREDUMP_EXE=/usr/bin/qa-fixture",
        std::string("COREDUMP_FILENAME=") + (missing ? "/tmp/qa-absent-core" : "/tmp/qa-core"),
        "_SYSTEMD_UNIT=systemd-coredump@1-2-1000.service", "_BOOT_ID=qa-boot"};
    if (const char *payload = std::getenv("QA_PAYLOAD_BYTES")) {
        entries.push_back("QA_PAYLOAD=" + std::string(std::atoi(payload), 'x'));
    }
    return 1;
}
int sd_journal_get_cursor(sd_journal *, char **out) {
    if(fault("cursor")) return -EIO;
    *out = strdup(("qa-cursor-" + std::to_string(position)).c_str()); return 0;
}
void sd_journal_restart_data(sd_journal *) { field = 0; }
int sd_journal_enumerate_data(sd_journal *, const void **out, size_t *length) {
    if (field >= static_cast<int>(entries.size())) return 0;
    *out = entries[field].data(); *length = entries[field].size(); ++field; return 1;
}
}
