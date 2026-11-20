#include "cve5.h"

#include "vercmp.h"

#include <QHash>
#include <QJsonArray>
#include <QRegularExpression>

namespace Cve5 {

QString normalise(const QString &name) {
    static const QRegularExpression gaps(R"([\s_]+)");
    return name.trimmed().toLower().replace(gaps, "-");
}

QString Affected::key() const { return normalise(product); }
QString Affected::vendorKey() const { return normalise(vendor); }

namespace {

double baseScore(const QJsonArray &metrics) {
    for (const char *kind : {"cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"}) {
        for (const QJsonValue &m : metrics) {
            const QJsonObject cvss = m.toObject().value(kind).toObject();
            if (cvss.contains("baseScore"))
                return cvss.value("baseScore").toDouble();
        }
    }
    return -1;
}

QString baseSeverity(const QJsonArray &metrics) {
    for (const char *kind : {"cvssV4_0", "cvssV3_1", "cvssV3_0"}) {
        for (const QJsonValue &m : metrics) {
            const QString s = m.toObject().value(kind).toObject().value("baseSeverity").toString();
            if (!s.isEmpty())
                return s;
        }
    }
    return {};
}

QList<Affected> readAffected(const QJsonArray &list, const QString &source) {
    QList<Affected> out;
    for (const QJsonValue &value : list) {
        const QJsonObject o = value.toObject();
        Affected a;
        a.vendor = o.value("vendor").toString();
        a.product = o.value("product").toString();
        a.collection = o.value("collectionURL").toString();
        a.package = o.value("packageName").toString();
        a.defaultStatus = o.value("defaultStatus").toString();
        a.source = source;
        for (const QJsonValue &f : o.value("programFiles").toArray())
            a.files << f.toString();
        for (const QJsonValue &v : o.value("versions").toArray()) {
            const QJsonObject r = v.toObject();
            if (r.value("versionType").toString() == "git")
                continue;
            a.versions.append({r.value("version").toString(), r.value("lessThan").toString(),
                               r.value("lessThanOrEqual").toString(), r.value("status").toString(),
                               r.value("versionType").toString()});
        }
        if (a.product.isEmpty() && a.package.isEmpty())
            continue;
        if (a.product.isEmpty())
            a.product = a.package;
        out.append(a);
    }
    return out;
}

// "v1.2.3" and "1.2.3" are versions; "n/a", "unspecified", "*" and "" are not.
QString clean(QString v) {
    v = v.trimmed();
    if (v.size() > 1 && (v.at(0) == 'v' || v.at(0) == 'V') && v.at(1).isDigit())
        v = v.mid(1);
    return v;
}
bool usable(const QString &v) { return usableVersion(v); }

QString normaliseVersion(const QString &raw) {
    // The same few thousand strings come up again and again in one check.
    static QHash<QString, QString> cache;
    const auto hit = cache.constFind(raw);
    if (hit != cache.constEnd())
        return hit.value();
    QString v = clean(raw);
    const int plus = v.indexOf('+');
    if (plus > 0)
        v = v.left(plus);
    static const QRegularExpression post(R"((\d)[-_.~]?(?:p|pl|patch|post)(\d+))", QRegularExpression::CaseInsensitiveOption);
    v.replace(post, "\\1.\\2");
    static const QRegularExpression beforeLetters(R"([-_.~]+(?=[A-Za-z]))");
    v.replace(beforeLetters, "");
    cache.insert(raw, v);
    return v;
}

int cmp(const QString &a, const QString &b) { return compareUpstream(a, b); }

// "7.3.*" as an upper bound: anything up to and including every 7.3.x.
bool withinWildcard(const QString &installed, const QString &prefix) {
    return cmp(installed, prefix) <= 0 || installed.startsWith(prefix + ".");
}

} // namespace

int compareUpstream(const QString &a, const QString &b) {
    return Vercmp::rpmvercmp(normaliseVersion(a), normaliseVersion(b));
}

bool usableVersion(const QString &raw) {
    const QString v = clean(raw);
    if (v.isEmpty() || !v.at(0).isDigit())
        return false;
    static const QRegularExpression hash(R"(^[0-9a-f]{7,64}$)");
    const bool letters = v.contains(QRegularExpression("[a-f]"));
    return !(letters && hash.match(v).hasMatch());
}

Record parse(const QJsonObject &record) {
    Record r;
    const QJsonObject meta = record.value("cveMetadata").toObject();
    r.id = meta.value("cveId").toString();
    r.state = meta.value("state").toString();
    r.published = meta.value("datePublished").toString();
    r.updated = meta.value("dateUpdated").toString();
    const QJsonObject containers = record.value("containers").toObject();
    const QJsonObject cna = containers.value("cna").toObject();
    r.title = cna.value("title").toString();
    for (const QJsonValue &d : cna.value("descriptions").toArray()) {
        const QJsonObject o = d.toObject();
        if (o.value("lang").toString().startsWith("en") || r.description.isEmpty())
            r.description = o.value("value").toString();
        if (o.value("lang").toString().startsWith("en"))
            break;
    }
    const QJsonArray rejected = cna.value("rejectedReasons").toArray();
    if (r.description.isEmpty() && !rejected.isEmpty())
        r.description = rejected.at(0).toObject().value("value").toString();
    r.score = baseScore(cna.value("metrics").toArray());
    r.severity = baseSeverity(cna.value("metrics").toArray());
    r.affected = readAffected(cna.value("affected").toArray(), "cna");
    for (const QJsonValue &adp : containers.value("adp").toArray()) {
        const QJsonObject o = adp.toObject();
        if (r.score < 0) {
            r.score = baseScore(o.value("metrics").toArray());
            r.severity = baseSeverity(o.value("metrics").toArray());
        }
        r.affected += readAffected(o.value("affected").toArray(), "adp");
    }
    return r;
}

Evaluation evaluate(const QString &installed, const Affected &affected) {
    bool anyUsable = false, hitAffected = false, hitUnaffected = false;
    // True while every readable entry is an affected range with an upper
    // bound: then a version above them all is unaffected whatever the
    // defaultStatus says (Ghostscript's CVE-2026-39919 lists "0 < 10.08.0"
    // with default "affected").
    bool onlyBoundedAffected = true;
    QString fixedIn, why;
    auto offerFix = [&](const QString &v) {
        if (usable(v) && cmp(v, installed) > 0 && (fixedIn.isEmpty() || cmp(v, fixedIn) < 0))
            fixedIn = v;
    };

    for (const Range &r : affected.versions) {
        QString low = clean(r.version), lt = clean(r.lessThan), lte = clean(r.lessThanOrEqual);
        // Some records put the operator in the version: "< 1.2.3", "<= 3.54.1".
        if (lt.isEmpty() && lte.isEmpty()) {
            if (low.startsWith("<=")) {
                lte = clean(low.mid(2));
                low = "0";
            } else if (low.startsWith('<')) {
                lt = clean(low.mid(1));
                low = "0";
            }
        }
        bool match;
        if (!lt.isEmpty() || !lte.isEmpty()) {
            const bool strict = !lt.isEmpty();
            const QString upper = strict ? lt : lte;
            bool upperOk;
            if (upper == "*") {
                upperOk = true;
            } else if (upper.endsWith(".*") && usable(upper.chopped(2))) {
                upperOk = withinWildcard(installed, upper.chopped(2));
            } else if (usable(upper)) {
                const int c = cmp(installed, upper);
                upperOk = strict ? c < 0 : c <= 0;
            } else {
                continue;
            }
            bool lowerOk = true;
            if (usable(low) && low != "0")
                lowerOk = cmp(installed, low) >= 0;
            else if (!low.isEmpty() && low != "0" && low != "*" && !usable(low) && upper == "*")
                continue; // "unspecified" up to "*" says nothing
            anyUsable = true;
            match = lowerOk && upperOk;
            if (r.status != "affected" || upper == "*")
                onlyBoundedAffected = false;
            if (r.status == "affected" && strict)
                offerFix(lt);
        } else {
            if (!usable(low))
                continue;
            anyUsable = true;
            match = cmp(installed, low) == 0;
            onlyBoundedAffected = false;
        }
        if (r.status == "unaffected" && (lte == "*" || lte.endsWith(".*") || (lt.isEmpty() && lte.isEmpty())))
            offerFix(low);
        if (match && r.status == "affected") {
            hitAffected = true;
            if (why.isEmpty())
                why = QString("in an affected range (%1%2%3)")
                          .arg(low.isEmpty() ? "0" : low, lt.isEmpty() ? " to " : " below ",
                               lt.isEmpty() ? lte : lt);
        } else if (match && r.status == "unaffected") {
            hitUnaffected = true;
        }
    }

    Evaluation e;
    e.fixedIn = fixedIn;
    if (hitUnaffected) {
        e.verdict = Verdict::Unaffected;
        e.reason = "listed as unaffected";
    } else if (hitAffected) {
        e.verdict = Verdict::Affected;
        e.reason = why;
    } else if (!anyUsable) {
        e.verdict = Verdict::Unknown;
        e.reason = "no versions Ward can read";
    } else if (affected.defaultStatus == "affected" && !onlyBoundedAffected) {
        e.verdict = Verdict::Affected;
        e.reason = "not in any listed range, and the record's default is affected";
    } else {
        e.verdict = Verdict::Unaffected;
        e.reason = onlyBoundedAffected && affected.defaultStatus == "affected"
                       ? "above every affected range the record lists"
                       : "not in any listed range";
    }
    return e;
}

} // namespace Cve5
