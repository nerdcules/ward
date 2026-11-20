#include "osv.h"

#include "cve5.h"
#include "net.h"
#include "store.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QSet>

namespace Osv {

namespace {

const QString kBatch = QStringLiteral("https://api.osv.dev/v1/querybatch");
const QString kVuln = QStringLiteral("https://api.osv.dev/v1/vulns/");

QString key(const Projects::Dependency &d) { return d.ecosystem + "\x1f" + d.name + "\x1f" + d.version; }

// The ecosystems' own order where it differs from upstream numbering is not
// modelled; all four use dotted numbers with pre-release suffixes, which
// Cve5::compareUpstream orders.
int cmp(const QString &a, const QString &b) { return Cve5::compareUpstream(a, b); }

} // namespace

Advisory parse(const QJsonObject &v) {
    Advisory a;
    a.id = v.value("id").toString();
    a.summary = v.value("summary").toString();
    a.details = v.value("details").toString();
    a.severity = v.value("database_specific").toObject().value("severity").toString();
    for (const QJsonValue &alias : v.value("aliases").toArray())
        if (alias.toString().startsWith("CVE-"))
            a.aliases << alias.toString();
    if (a.id.startsWith("CVE-") && !a.aliases.contains(a.id))
        a.aliases.prepend(a.id);
    a.affected = v.value("affected").toArray();
    return a;
}

QString fixedVersion(const Advisory &a, const QString &ecosystem, const QString &name, const QString &version) {
    QString best;
    for (const QJsonValue &v : a.affected) {
        const QJsonObject pkg = v.toObject().value("package").toObject();
        if (pkg.value("ecosystem").toString() != ecosystem ||
            pkg.value("name").toString().compare(name, Qt::CaseInsensitive) != 0)
            continue;
        for (const QJsonValue &range : v.toObject().value("ranges").toArray())
            for (const QJsonValue &event : range.toObject().value("events").toArray()) {
                const QString fixed = event.toObject().value("fixed").toString();
                if (!fixed.isEmpty() && cmp(fixed, version) > 0 && (best.isEmpty() || cmp(fixed, best) < 0))
                    best = fixed;
            }
    }
    return best;
}

Run check(const QList<Projects::Dependency> &deps, const QString &cacheDir, const Store &store,
          const QHash<QString, Feeds::Kev> &kev) {
    Run run;
    QStringList keys;
    QHash<QString, Projects::Dependency> unique;
    for (const Projects::Dependency &d : deps)
        if (!unique.contains(key(d))) {
            unique.insert(key(d), d);
            keys << key(d);
        }
    run.packages = keys.size();

    // Which advisories each version has, and when each last changed.
    QHash<QString, QStringList> ids;
    QHash<QString, QString> modified;
    for (int i = 0; i < keys.size(); i += 1000) {
        QJsonArray queries;
        const QStringList batch = keys.mid(i, 1000);
        for (const QString &k : batch) {
            const Projects::Dependency &d = unique[k];
            queries.append(QJsonObject{{"package", QJsonObject{{"ecosystem", d.ecosystem}, {"name", d.name}}},
                                       {"version", d.version}});
        }
        QString error;
        const QByteArray body =
            Net::postJson(QUrl(kBatch), QJsonDocument(QJsonObject{{"queries", queries}}).toJson(QJsonDocument::Compact), &error);
        const QJsonArray results = QJsonDocument::fromJson(body).object().value("results").toArray();
        if (results.size() != batch.size()) {
            run.error = error.isEmpty() ? QString("OSV's answer didn't match the question") : error;
            return run;
        }
        for (int j = 0; j < batch.size(); ++j)
            for (const QJsonValue &v : results.at(j).toObject().value("vulns").toArray()) {
                ids[batch.at(j)] << v.toObject().value("id").toString();
                modified.insert(v.toObject().value("id").toString(), v.toObject().value("modified").toString());
            }
    }
    run.vulnerable = ids.size();

    // Each advisory once, from the cache unless OSV changed it since.
    const QString dir = cacheDir + "/osv";
    QDir().mkpath(dir);
    QHash<QString, Advisory> advisories;
    for (auto it = modified.constBegin(); it != modified.constEnd(); ++it) {
        const QString path = dir + "/" + QString(it.key()).replace('/', '_') + ".json";
        QJsonObject v;
        QFile f(path);
        if (f.open(QIODevice::ReadOnly))
            v = QJsonDocument::fromJson(f.readAll()).object();
        f.close();
        if (v.isEmpty() || v.value("modified").toString() < it.value()) {
            QString error;
            const QByteArray body = Net::get(QUrl(kVuln + it.key()), &error);
            const QJsonObject fresh = QJsonDocument::fromJson(body).object();
            if (!fresh.isEmpty()) {
                v = fresh;
                QSaveFile out(path);
                if (out.open(QIODevice::WriteOnly)) {
                    out.write(body);
                    out.commit();
                }
                ++run.fetched;
            }
        }
        if (!v.isEmpty())
            advisories.insert(it.key(), parse(v));
    }
    run.advisories = advisories.size();

    // A finding per advisory, project and dependency version.
    QSet<QString> seen;
    for (const Projects::Dependency &d : deps) {
        for (const QString &id : ids.value(key(d))) {
            if (!advisories.contains(id))
                continue;
            const Advisory &a = advisories[id];
            Matcher::Finding f;
            f.layer = "project";
            f.package = QFileInfo(d.project).fileName();
            f.location = d.project;
            f.component = d.name;
            f.version = d.version;
            f.upstream = d.version;
            f.ecosystem = d.ecosystem;
            f.cve = a.aliases.isEmpty() ? a.id : a.aliases.first();
            f.advisory = a.id;
            if (seen.contains(f.id() + "@" + f.location))
                continue;
            seen.insert(f.id() + "@" + f.location);
            f.verdict = "affected";
            f.source = "osv";
            f.match = "vendor"; // OSV matches the ecosystem's own package name exactly
            f.title = a.summary;
            f.description = a.details.left(1500);
            f.severity = a.severity;
            f.fixedIn = fixedVersion(a, d.ecosystem, d.name, d.version);
            f.reason = QString("%1 lists %2 %3 as affected").arg(a.id, d.name, d.version) +
                       (d.dev ? QString(" (a development-only dependency)") : QString());
            Cve5::Record r;
            if (f.cve.startsWith("CVE-") && store.record(f.cve, &r)) {
                f.score = r.score;
                f.published = r.published;
                if (f.severity.isEmpty())
                    f.severity = r.severity;
            }
            if (kev.contains(f.cve)) {
                f.kev = true;
                f.kevAdded = kev.value(f.cve).dateAdded;
            }
            run.findings << f;
        }
    }
    return run;
}

} // namespace Osv
