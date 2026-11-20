#include "report.h"

#include "cve5.h"
#include "matcher.h"

#include <QHash>
#include <algorithm>

namespace Report {

QList<PackageSummary> byPackage(const QJsonArray &list) {
    QHash<QString, PackageSummary> map;
    for (const QJsonValue &v : list) {
        const Matcher::Finding f = Matcher::Finding::fromJson(v.toObject());
        if (f.verdict != "affected")
            continue;
        PackageSummary &s = map[f.package];
        s.package = f.package;
        s.version = f.version;
        s.kernel = f.kernel;
        ++s.count;
        s.kev += f.kev;
        if (f.applies.isEmpty())
            ++s.open;
        else if (f.priority == "now")
            ++s.now;
        else if (f.priority == "soon")
            ++s.soon;
        else
            ++s.dismissed;
        if (!f.updateTo.isEmpty())
            s.updateTo = f.updateTo;
        if (!f.fixedIn.isEmpty() && (s.fixAll.isEmpty() || Cve5::compareUpstream(f.fixedIn, s.fixAll) > 0))
            s.fixAll = f.fixedIn;
    }
    QList<PackageSummary> out = map.values();
    std::sort(out.begin(), out.end(), [](const PackageSummary &a, const PackageSummary &b) {
        if (a.rank() != b.rank())
            return a.rank() < b.rank();
        if (a.now + a.soon != b.now + b.soon)
            return a.now + a.soon > b.now + b.soon;
        if (a.kev != b.kev)
            return a.kev > b.kev;
        if (a.count != b.count)
            return a.count > b.count;
        return a.package < b.package;
    });
    return out;
}

Totals totals(const QJsonArray &list) {
    Totals t;
    for (const QJsonValue &v : list) {
        const Matcher::Finding f = Matcher::Finding::fromJson(v.toObject());
        if (f.verdict != "affected") {
            ++t.unknown;
            continue;
        }
        ++t.affected;
        t.kev += f.kev;
        if (f.applies.isEmpty())
            ++t.open;
        else if (f.priority == "now")
            ++t.now;
        else if (f.priority == "soon")
            ++t.soon;
        t.byClaude += f.triagedBy == "claude";
        t.byWard += f.triagedBy == "ward";
    }
    return t;
}

QString mitigation(const QJsonObject &cache, const QString &package, const QString &version) {
    return cache.value("mitigation@" + package + "@" + version).toString();
}

} // namespace Report
