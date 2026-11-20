#pragma once

#include "feeds.h"
#include "matcher.h"
#include "projects.h"

#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QString>

class Store;

// OSV.dev (api.osv.dev) for project dependencies: one querybatch per 1,000
// packages says which advisories each version has, then each advisory is
// fetched once and kept in the cache (re-fetched when OSV says it changed).
namespace Osv {

struct Advisory {
    QString id, summary, details, severity; // severity: GitHub's (LOW...CRITICAL) when given
    QStringList aliases;                     // CVE ids among them
    QJsonArray affected;                     // OSV's affected[], for the fixed version
};
Advisory parse(const QJsonObject &vuln);

// The lowest "fixed" event above `version` for this package in an advisory;
// empty when none is named.
QString fixedVersion(const Advisory &a, const QString &ecosystem, const QString &name, const QString &version);

struct Run {
    QList<Matcher::Finding> findings;
    int packages = 0, vulnerable = 0, advisories = 0, fetched = 0;
    QString error;
};

// Looks up every dependency (deduplicated by ecosystem, name and version)
// and turns each advisory into a finding per project. The finding's cve is
// the advisory's CVE alias when it has one (so scores and CISA's list apply),
// else the advisory's own id.
Run check(const QList<Projects::Dependency> &deps, const QString &cacheDir, const Store &store,
          const QHash<QString, Feeds::Kev> &kev);

} // namespace Osv
