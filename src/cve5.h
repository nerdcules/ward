#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

// CVE records in the CVE JSON 5 format that CVE.org publishes (the
// CVEProject/cvelistV5 repository). Only the parts Ward matches on are kept.
namespace Cve5 {

// One entry of an "affected" block's versions list.
struct Range {
    QString version, lessThan, lessThanOrEqual, status, type;
};

// One product a record names: from the CNA (who wrote the record) or an ADP
// (CISA's added data, often with CPEs).
struct Affected {
    QString vendor, product, collection, package, defaultStatus, source;
    QList<Range> versions;
    QStringList files; // programFiles: source files the flaw is in (the kernel's records name them)
    QString key() const;       // normalised product, what packages are looked up by
    QString vendorKey() const; // normalised vendor
};

struct Record {
    QString id, state, published, updated, title, description, severity;
    double score = -1; // the CNA's CVSS base score, else an ADP's; -1 when none
    QList<Affected> affected;
};

Record parse(const QJsonObject &record);

// Lowercase, with runs of spaces and underscores as one hyphen:
// "Linux Kernel" and "linux_kernel" both give "linux-kernel".
QString normalise(const QString &name);

// Orders two upstream versions as their projects mean them, which pacman's
// order doesn't always: "+build" metadata is dropped (glibc's 2.44+r50+g18...
// is 2.44), a p/pl/patch/post number is a later release (OpenSSH's 10.6p1
// comes after 10.6), and a separator before letters doesn't count (avahi's
// 0.9-rc4 comes before 0.9rc5). Pre-releases (rc, alpha, beta...) still
// come before the release.
int compareUpstream(const QString &a, const QString &b);

// A version Ward can compare: starts with a digit and isn't a commit hash.
bool usableVersion(const QString &v);

enum class Verdict { Affected, Unaffected, Unknown };

struct Evaluation {
    Verdict verdict = Verdict::Unknown;
    QString fixedIn; // the lowest version above the installed one said to be fixed
    QString reason;  // which rule decided, for `ward show`
};

// Is upstream version `installed` affected? Follows the schema: a version with
// lessThan/lessThanOrEqual is a range, otherwise one exact version; "7.3.*"
// means any 7.3.x. An unaffected match beats an affected one (the kernel's
// records carve fixed stable branches out of a wide affected range); with no
// match the defaultStatus decides, unless every entry is an affected range
// with an upper bound (then the version is above them all, and unaffected);
// with none of either the product is taken as unaffected when the list had
// versions Ward could read. Entries of
// type "git" (commit hashes) are skipped.
Evaluation evaluate(const QString &installed, const Affected &affected);

} // namespace Cve5
