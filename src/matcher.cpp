#include "matcher.h"

#include "cve5.h"
#include "store.h"
#include "vercmp.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QSet>
#include <QUrl>
#include <algorithm>

namespace Matcher {

namespace {

const QStringList kRegistries{"npmjs", "pypi.org", "crates.io", "rubygems", "golang", "pkg.go.dev", "maven",
                              "nuget", "packagist", "hex.pm", "pub.dev", "cocoapods", "cpan", "hackage",
                              "pkgs.racket", "swiftpackageindex", "github.com/advisories"};

bool fromRegistry(const QString &collection) {
    const QString c = collection.toLower();
    for (const QString &r : kRegistries)
        if (c.contains(r))
            return true;
    return false;
}

int matchRank(const QString &match) { return match == "tracker" ? 0 : match == "vendor" ? 1 : 2; }

Finding base(const Inventory::Package &p) {
    Finding f;
    f.package = p.name;
    f.version = p.version;
    f.upstream = Vercmp::upstream(p.version);
    f.foreign = p.foreign;
    f.kernel = p.kernel;
    return f;
}

// One lookup key and what a row must satisfy to count for it.
struct Key {
    QString key;
    bool pypiOnly = false; // python-x looked up as x
};

} // namespace

Names loadNames(const QByteArray &shipped, const QByteArray &user) {
    Names names;
    for (const QByteArray &source : {shipped, user}) {
        const QJsonObject o = QJsonDocument::fromJson(source).object();
        for (auto it = o.begin(); it != o.end(); ++it) {
            if (it.key().startsWith('_'))
                continue; // comments
            NameRule rule;
            for (const QJsonValue &v : it.value().toObject().value("products").toArray())
                rule.products << Cve5::normalise(v.toString());
            for (const QJsonValue &v : it.value().toObject().value("vendors").toArray())
                rule.vendors << Cve5::normalise(v.toString());
            names.insert(it.key(), rule);
        }
    }
    return names;
}

QJsonObject Finding::toJson() const {
    QJsonObject o{{"id", id()},
                  {"cve", cve},
                  {"package", package},
                  {"version", version},
                  {"upstream", upstream},
                  {"verdict", verdict},
                  {"source", source},
                  {"match", match},
                  {"kev", kev},
                  {"foreign", foreign},
                  {"kernel", kernel}};
    auto put = [&](const char *k, const QString &v) {
        if (!v.isEmpty())
            o.insert(k, v);
    };
    put("vendor", vendor);
    put("product", product);
    put("group", group);
    put("fixedIn", fixedIn);
    put("reason", reason);
    put("title", title);
    put("description", description);
    put("published", published);
    put("severity", severity);
    put("kevAdded", kevAdded);
    put("where", where);
    put("applies", applies);
    put("priority", priority);
    put("why", why);
    put("triagedBy", triagedBy);
    put("updateTo", updateTo);
    if (layer != "system")
        o.insert("layer", layer);
    put("component", component);
    put("location", location);
    put("ecosystem", ecosystem);
    put("advisory", advisory);
    if (!files.isEmpty())
        o.insert("files", QJsonArray::fromStringList(files));
    if (score >= 0)
        o.insert("score", score);
    return o;
}

Finding Finding::fromJson(const QJsonObject &o) {
    Finding f;
    f.cve = o.value("cve").toString();
    f.package = o.value("package").toString();
    f.version = o.value("version").toString();
    f.upstream = o.value("upstream").toString();
    f.verdict = o.value("verdict").toString();
    f.source = o.value("source").toString();
    f.match = o.value("match").toString();
    f.vendor = o.value("vendor").toString();
    f.product = o.value("product").toString();
    f.group = o.value("group").toString();
    f.fixedIn = o.value("fixedIn").toString();
    f.reason = o.value("reason").toString();
    f.title = o.value("title").toString();
    f.description = o.value("description").toString();
    f.published = o.value("published").toString();
    f.severity = o.value("severity").toString();
    f.kevAdded = o.value("kevAdded").toString();
    f.score = o.value("score").toDouble(-1);
    f.kev = o.value("kev").toBool();
    f.foreign = o.value("foreign").toBool();
    f.kernel = o.value("kernel").toBool();
    f.where = o.value("where").toString();
    f.applies = o.value("applies").toString();
    f.priority = o.value("priority").toString();
    f.why = o.value("why").toString();
    f.triagedBy = o.value("triagedBy").toString();
    f.updateTo = o.value("updateTo").toString();
    f.layer = o.value("layer").toString("system");
    f.component = o.value("component").toString();
    f.location = o.value("location").toString();
    f.ecosystem = o.value("ecosystem").toString();
    f.advisory = o.value("advisory").toString();
    for (const QJsonValue &v : o.value("files").toArray())
        f.files << v.toString();
    return f;
}

QList<Finding> run(const QList<Inventory::Package> &packages, const QList<Feeds::ArchGroup> &arch,
                   const QHash<QString, Feeds::Kev> &kev, const Store &store, const Names &names) {
    QList<Finding> out;
    QHash<QString, const Inventory::Package *> byName;
    for (const auto &p : packages)
        byName.insert(p.name, &p);

    // Arch's tracker. `decided` holds every (CVE, package) it has an answer
    // for, affected or not, so CVE.org can't overrule it.
    QSet<QString> decided;
    for (const Feeds::ArchGroup &g : arch) {
        for (const QString &name : g.packages) {
            const Inventory::Package *p = byName.value(name);
            if (!p)
                continue;
            bool affected;
            QString reason;
            if (!g.fixed.isEmpty()) {
                affected = Vercmp::compare(p->version, g.fixed) < 0;
                reason = affected ? QString("older than %1, which fixed it").arg(g.fixed)
                                  : QString("at or past %1, which fixed it").arg(g.fixed);
            } else if (g.status == "Vulnerable" && Vercmp::compare(p->version, g.affected) <= 0) {
                affected = true;
                reason = QString("no fixed package yet; %1 is the version reported").arg(g.affected);
            } else {
                // No fix recorded, but the installed package is newer than the
                // one reported: the tracker can't say (many such groups are
                // years old, such as openssl's AVG for CVE-2022-2068), so
                // CVE.org's record decides instead.
                continue;
            }
            for (const QString &cve : g.issues) {
                Finding f = base(*p);
                f.cve = cve;
                decided.insert(f.id());
                if (!affected)
                    continue;
                f.verdict = "affected";
                f.source = "arch";
                f.match = "tracker";
                f.group = g.name;
                f.fixedIn = g.fixed;
                f.severity = g.severity;
                f.reason = reason;
                out.append(f);
            }
        }
    }

    for (const Inventory::Package &p : packages) {
        QString name = p.name;
        if (name.startsWith("lib32-"))
            name = name.mid(6);
        const NameRule rule = names.value(p.name, names.value(name));

        QList<Key> keys{{Cve5::normalise(name)}};
        if (name.startsWith("python-"))
            keys.append({Cve5::normalise(name.mid(7)), true});
        QStringList vendors = rule.vendors;
        if (p.kernel) {
            keys = {{"linux"}, {"linux-kernel"}};
            if (vendors.isEmpty())
                vendors = {"linux"};
        }
        for (const QString &extra : rule.products)
            keys.append({extra});

        QStringList lookup;
        QHash<QString, bool> pypiOnly;
        for (const Key &k : keys) {
            lookup << k.key;
            pypiOnly.insert(k.key, pypiOnly.value(k.key, true) && k.pypiOnly);
        }

        // Every row for this package, grouped by CVE.
        QHash<QString, QList<Store::Row>> byCve;
        for (const Store::Row &row : store.rows(lookup)) {
            const Cve5::Affected &a = row.affected;
            const bool pypi = a.collection.contains("pypi", Qt::CaseInsensitive);
            if (pypiOnly.value(a.key()) && !(pypi || a.collection.isEmpty()))
                continue;
            if (fromRegistry(a.collection) && !(pypi && name.startsWith("python-")))
                continue;
            if (a.package.contains('/') || a.package.contains(':'))
                continue;
            if (!vendors.isEmpty() && !vendors.contains(a.vendorKey()))
                continue;
            byCve[row.record.id].append(row);
        }

        // A package from outside the repos (the AUR, or built here) shares
        // its name with other projects too often (this machine's own "drift"
        // matched two other projects called Drift, by vendors hulumi and
        // thinkupthemes). Without a names.json rule, a record
        // counts only when its vendor appears in the package's URL.
        if (p.foreign && !names.contains(p.name)) {
            const QString url = Cve5::normalise(p.url);
            for (auto it = byCve.begin(); it != byCve.end();) {
                QList<Store::Row> &rows = it.value();
                rows.removeIf([&](const Store::Row &row) {
                    const QString vendor = row.affected.vendorKey();
                    return url.isEmpty() || vendor.isEmpty() || !url.contains(vendor);
                });
                it = rows.isEmpty() ? byCve.erase(it) : std::next(it);
            }
        }

        const QString upstream = Vercmp::upstream(p.version);
        for (auto it = byCve.begin(); it != byCve.end(); ++it) {
            Finding f = base(p);
            f.cve = it.key();
            if (decided.contains(f.id()))
                continue;
            // The CNA's own rows decide when they can; CISA's ADP rows only
            // when the CNA's say nothing usable.
            const Store::Row *chosen = nullptr;
            Cve5::Evaluation chosenEval;
            for (const char *source : {"cna", "adp"}) {
                for (const Store::Row &row : it.value()) {
                    if (row.affected.source != source)
                        continue;
                    const Cve5::Evaluation e = Cve5::evaluate(upstream, row.affected);
                    const auto rank = [](Cve5::Verdict v) {
                        return v == Cve5::Verdict::Affected ? 0 : v == Cve5::Verdict::Unaffected ? 1 : 2;
                    };
                    if (!chosen || rank(e.verdict) < rank(chosenEval.verdict)) {
                        chosen = &row;
                        chosenEval = e;
                    }
                }
                if (chosen && chosenEval.verdict != Cve5::Verdict::Unknown)
                    break;
            }
            if (!chosen || chosenEval.verdict == Cve5::Verdict::Unaffected)
                continue;
            const Cve5::Record &r = chosen->record;
            f.verdict = chosenEval.verdict == Cve5::Verdict::Affected ? "affected" : "unknown";
            f.source = chosen->affected.source;
            f.match = vendors.isEmpty() && !p.foreign ? "name" : "vendor";
            f.vendor = chosen->affected.vendor;
            f.files = chosen->affected.files;
            f.product = chosen->affected.product;
            f.fixedIn = chosenEval.fixedIn;
            f.reason = chosenEval.reason;
            f.title = r.title;
            f.description = r.description;
            f.published = r.published;
            f.severity = r.severity;
            f.score = r.score;
            out.append(f);
        }
    }

    for (Finding &f : out) {
        if (kev.contains(f.cve)) {
            f.kev = true;
            f.kevAdded = kev.value(f.cve).dateAdded;
        }
        // Arch findings take the record's text and score when Ward has it.
        if (f.source == "arch") {
            Cve5::Record r;
            if (store.record(f.cve, &r)) {
                f.title = r.title;
                f.description = r.description;
                f.published = r.published;
                f.score = r.score;
            }
        }
    }
    sort(out);
    return out;
}

void sort(QList<Finding> &findings) {
    std::stable_sort(findings.begin(), findings.end(), [](const Finding &a, const Finding &b) {
        if (a.kev != b.kev)
            return a.kev;
        if ((a.verdict == "affected") != (b.verdict == "affected"))
            return a.verdict == "affected";
        if (matchRank(a.match) != matchRank(b.match))
            return matchRank(a.match) < matchRank(b.match);
        if (a.score != b.score)
            return a.score > b.score;
        return a.id() < b.id();
    });
}

} // namespace Matcher
