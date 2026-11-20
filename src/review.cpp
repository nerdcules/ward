#include "review.h"

#include "cve5.h"
#include "exposure.h"
#include "paths.h"
#include "triage.h"
#include "vercmp.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QSaveFile>
#include <QSet>
#include <algorithm>

namespace Review {

namespace {

QString cacheKey(const Matcher::Finding &f) { return f.cve + "@" + f.package + "@" + f.version; }

// lib32-x is the 32-bit build of x: an answer for x at the same upstream
// version is reused for it (on 2026-11-20, glibc and lib32-glibc took a call
// each for the same 18 CVEs).
QString baseName(const QString &package) { return package.startsWith("lib32-") ? package.mid(6) : package; }
QString sharedKey(const Matcher::Finding &f) {
    return "upstream:" + f.cve + "@" + baseName(f.package) + "@" + Vercmp::upstream(f.version);
}

QJsonObject readCache(const QString &path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? QJsonDocument::fromJson(f.readAll()).object() : QJsonObject();
}

void writeCache(const QString &path, const QJsonObject &cache) {
    QSaveFile f(path);
    if (f.open(QIODevice::WriteOnly)) {
        f.write(QJsonDocument(cache).toJson(QJsonDocument::Compact));
        f.commit();
    }
}

bool settled(const Matcher::Finding &f) { return !f.applies.isEmpty(); }

void fromCache(Matcher::Finding &f, const QJsonObject &cache) {
    QJsonObject c = cache.value(cacheKey(f)).toObject();
    if (c.isEmpty() && f.package.startsWith("lib32-"))
        c = cache.value(sharedKey(f)).toObject();
    if (c.isEmpty())
        return;
    f.applies = c.value("applies").toString();
    f.priority = c.value("priority").toString();
    f.why = c.value("why").toString();
    f.triagedBy = c.value("by").toString();
}

int urgency(const Matcher::Finding &f) { return (f.kev ? 100 : 0) + int(std::max(0.0, f.score) * 5); }

} // namespace

QJsonObject addExposure(QList<Matcher::Finding> &findings, const QList<Inventory::Package> &packages) {
    QHash<QString, Exposure::Kernel> kernels;
    for (const Inventory::Package &p : packages)
        if (p.kernel)
            kernels.insert(p.name, Exposure::readKernel(p.name));

    QStringList affected;
    for (Matcher::Finding &f : findings) {
        if (f.verdict != "affected")
            continue;
        if (!affected.contains(f.package))
            affected << f.package;
        if (!f.kernel || !kernels.contains(f.package))
            continue;
        const Exposure::Kernel &k = kernels.value(f.package);
        f.where = Exposure::kernelWhere(k, f.files);
        if (!k.running) {
            f.applies = "no";
            f.priority = "later";
            f.why = QString("%1 is installed but isn't the running kernel.").arg(f.package);
            f.triagedBy = "ward";
        } else if (f.where == "other-arch") {
            f.applies = "no";
            f.priority = "later";
            f.why = "The flaw is in code for another processor architecture.";
            f.triagedBy = "ward";
        } else if (f.where == "not-loaded") {
            // Some modules load on demand, so this lowers the priority without
            // ruling the flaw out.
            f.applies = "unclear";
            f.priority = "later";
            f.why = "The flaw is in a kernel module that isn't loaded now (" + f.files.join(", ").left(120) +
                    "); some modules load on demand.";
            f.triagedBy = "ward";
        }
    }

    QJsonObject out;
    const QHash<QString, Exposure::Package> exposure = Exposure::forPackages(affected);
    for (auto it = exposure.constBegin(); it != exposure.constEnd(); ++it)
        out.insert(it.key(), QJsonObject{{"summary", it.value().summary()}, {"detail", it.value().toJson()}});
    for (auto it = kernels.constBegin(); it != kernels.constEnd(); ++it)
        out.insert(it.key(), QJsonObject{{"summary", it.value().running
                                                         ? QString("the running kernel (%1)").arg(it.value().release)
                                                         : QString("installed, not running")}});
    return out;
}

QHash<QString, QString> pendingUpdates(QString *error) {
    QHash<QString, QString> out;
    QProcess p;
    p.start("checkupdates", {"--nocolor"});
    if (!p.waitForFinished(300000)) {
        if (error)
            *error = "checkupdates did not finish";
        return out;
    }
    // Exit 2 means nothing is waiting; 1 is a failure.
    if (p.exitCode() == 1 && error)
        *error = QString::fromUtf8(p.readAllStandardError()).trimmed().left(200);
    for (const QString &line : QString::fromUtf8(p.readAllStandardOutput()).split('\n', Qt::SkipEmptyParts)) {
        const QStringList f = line.split(' ', Qt::SkipEmptyParts); // name old -> new
        if (f.size() >= 4)
            out.insert(f.at(0), f.at(3));
    }
    return out;
}

void addUpdates(QList<Matcher::Finding> &findings, const QHash<QString, QString> &pending) {
    for (Matcher::Finding &f : findings) {
        const QString next = pending.value(f.package);
        if (next.isEmpty())
            continue;
        // An update counts as the fix when it reaches the fixed version (Arch's
        // own for the tracker, upstream's for CVE.org), or when no fix is named.
        const bool fixes = f.fixedIn.isEmpty() ||
                           (f.source == "arch" ? Vercmp::compare(next, f.fixedIn) >= 0
                                               : Cve5::compareUpstream(Vercmp::upstream(next), f.fixedIn) >= 0);
        if (fixes)
            f.updateTo = next;
    }
}

void applyCache(QList<Matcher::Finding> &findings, const QString &cachePath) {
    const QJsonObject cache = readCache(cachePath);
    for (Matcher::Finding &f : findings)
        if (!settled(f) && f.verdict == "affected")
            fromCache(f, cache);
}

TriageRun triage(QList<Matcher::Finding> &findings, const QJsonObject &exposure, const QString &cachePath,
                 const QString &claude, const QString &model, int maxCalls, int perCall, QTextStream &log) {
    TriageRun run;
    QJsonObject cache = readCache(cachePath);

    // Packages with unsettled findings, most urgent first.
    QHash<QString, QList<int>> open;
    for (int i = 0; i < findings.size(); ++i) {
        Matcher::Finding &f = findings[i];
        if (f.verdict != "affected" || settled(f))
            continue;
        fromCache(f, cache);
        if (settled(f)) {
            ++run.cached;
            continue;
        }
        open[f.package].append(i);
    }
    QStringList order = open.keys();
    auto top = [&](const QString &p) {
        int best = 0;
        for (int i : open.value(p))
            best = std::max(best, urgency(findings.at(i)));
        return best;
    };
    // Most urgent first, but each lib32- package after its 64-bit one, so it
    // can take that package's answers instead of a call of its own.
    std::sort(order.begin(), order.end(), [&](const QString &a, const QString &b) {
        const bool la = a.startsWith("lib32-"), lb = b.startsWith("lib32-");
        if (la != lb)
            return lb;
        return top(a) > top(b);
    });

    for (const QString &package : order) {
        QList<int> indexes;
        for (int i : open.value(package)) {
            fromCache(findings[i], cache);
            if (settled(findings.at(i)))
                ++run.cached;
            else
                indexes << i;
        }
        std::sort(indexes.begin(), indexes.end(),
                  [&](int a, int b) { return urgency(findings.at(a)) > urgency(findings.at(b)); });
        for (int start = 0; start < indexes.size(); start += perCall) {
            if (run.calls >= maxCalls) {
                run.left += indexes.size() - start;
                continue;
            }
            QList<Matcher::Finding> batch;
            for (int j = start; j < std::min<int>(start + perCall, indexes.size()); ++j)
                batch << findings.at(indexes.at(j));
            const QString summary = exposure.value(package).toObject().value("summary").toString();
            log << "Asking Claude about " << batch.size() << " CVE" << (batch.size() == 1 ? "" : "s") << " in "
                << package << "...\n";
            log.flush();
            const Triage::Answer answer =
                Triage::ask(claude, model, Triage::question(package, batch.first().version, summary, batch),
                            Paths::state() + "/triage-work");
            ++run.calls;
            run.seconds += answer.seconds;
            if (answer.costUsd > 0)
                run.costUsd += answer.costUsd;
            if (!answer.error.isEmpty()) {
                run.failed += batch.size();
                run.errors << package + ": " + answer.error;
                continue;
            }
            QHash<QString, Triage::Verdict> byCve;
            for (const Triage::Verdict &v : answer.verdicts)
                byCve.insert(v.cve, v);
            for (int j = start; j < std::min<int>(start + perCall, indexes.size()); ++j) {
                Matcher::Finding &f = findings[indexes.at(j)];
                if (!byCve.contains(f.cve)) {
                    ++run.failed;
                    continue;
                }
                const Triage::Verdict v = byCve.value(f.cve);
                f.applies = v.applies;
                f.priority = v.priority;
                f.why = v.why;
                f.triagedBy = "claude";
                const QJsonObject entry{
                    {"applies", v.applies}, {"priority", v.priority}, {"why", v.why}, {"by", "claude"}, {"model", model}};
                cache.insert(cacheKey(f), entry);
                if (!f.package.startsWith("lib32-"))
                    cache.insert(sharedKey(f), entry);
                ++run.triaged;
            }
            if (!answer.mitigation.isEmpty())
                cache.insert("mitigation@" + package + "@" + batch.first().version, answer.mitigation);
            writeCache(cachePath, cache);
        }
    }
    return run;
}

} // namespace Review
