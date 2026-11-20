#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QString>

// Reading the last check's results (findings.json), for the command line
// and the window alike.
namespace Report {

// One line per package: its CVEs by triage verdict, what the repos have,
// and the upstream version that clears every CVE with a known fix.
struct PackageSummary {
    QString package, version, fixAll, updateTo;
    int count = 0, kev = 0, now = 0, soon = 0, open = 0, dismissed = 0;
    bool kernel = false;
    int rank() const { return now ? 0 : soon ? 1 : open ? 2 : 3; }
};

// Most pressing first: now, soon, untriaged, then the rest.
QList<PackageSummary> byPackage(const QJsonArray &findings);

struct Totals {
    int affected = 0, unknown = 0, kev = 0, now = 0, soon = 0, open = 0, byClaude = 0, byWard = 0;
};
Totals totals(const QJsonArray &findings);

// The mitigation Claude suggested for a package at a version, if any, from
// the triage cache (triage.json).
QString mitigation(const QJsonObject &triageCache, const QString &package, const QString &version);

} // namespace Report
