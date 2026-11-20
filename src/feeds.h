#pragma once

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>
#include <QTextStream>

// The small feeds, fetched whole on every check and kept in the cache so a
// check without the network still has the last copy:
// - Arch's security tracker: advisory groups naming Arch packages and the
//   exact package version that fixed them.
// - CISA's Known Exploited Vulnerabilities: CVEs being exploited in the wild.
// - kernel.org's list of maintained kernel branches.
namespace Feeds {

const QString kArchUrl = QStringLiteral("https://security.archlinux.org/issues/all.json");
const QString kKernelUrl = QStringLiteral("https://www.kernel.org/releases.json");
const QString kKevUrl =
    QStringLiteral("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");

struct ArchGroup {
    QString name, status, severity, type, affected, fixed;
    QStringList packages, issues;
};
QList<ArchGroup> parseArch(const QByteArray &json);

struct Kev {
    QString cve, dateAdded, name, ransomware;
};
QHash<QString, Kev> parseKev(const QByteArray &json);

// kernel.org's current branches: is the installed kernel's branch still
// maintained? 7.2 was marked end-of-life on 2026-11-20, when 510 of the 527
// kernel CVEs matching 7.2.15 named a fix only in 7.3.x.
struct KernelBranch {
    QString moniker, version;
    bool eol = false;
};
QList<KernelBranch> parseKernels(const QByteArray &json);
// The branch (7.2) of an upstream kernel version (7.2.15), and kernel.org's
// entry for it; `found` is false when kernel.org no longer lists the branch,
// which also means it is unmaintained.
KernelBranch kernelBranch(const QList<KernelBranch> &branches, const QString &upstream, bool *found);

// Downloads the three into `cacheDir` (arch-all.json, kev.json, kernel-releases.json). A failed download
// keeps the copy from last time; the problem is written to `log`.
void refresh(const QString &cacheDir, QTextStream &log);

QByteArray read(const QString &path);

} // namespace Feeds
