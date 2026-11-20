#include "docker.h"

#include "store.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QSaveFile>
#include <QStandardPaths>

namespace Docker {

namespace {

QByteArray run(const QString &program, const QStringList &args, int ms = 60000, int *code = nullptr) {
    QProcess p;
    p.start(program, args);
    if (!p.waitForFinished(ms)) {
        p.kill();
        p.waitForFinished(5000);
        if (code)
            *code = -1;
        return {};
    }
    if (code)
        *code = p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1;
    return p.readAllStandardOutput();
}

double score(const QJsonObject &v) {
    const QJsonObject cvss = v.value("CVSS").toObject();
    for (const char *source : {"nvd", "ghsa", "redhat"}) {
        const QJsonObject c = cvss.value(source).toObject();
        if (c.contains("V3Score"))
            return c.value("V3Score").toDouble();
    }
    return -1;
}

} // namespace

QList<Image> parseImages(const QByteArray &images, const QByteArray &containers) {
    QHash<QString, Image> byId;
    QStringList order;
    for (const QByteArray &line : images.split('\n')) {
        const QJsonObject o = QJsonDocument::fromJson(line).object();
        QString id = o.value("ID").toString();
        if (id.isEmpty())
            continue;
        if (!id.startsWith("sha256:"))
            id = "sha256:" + id;
        const QString repo = o.value("Repository").toString(), tag = o.value("Tag").toString();
        Image &img = byId[id];
        if (img.id.isEmpty()) {
            img.id = id;
            order << id;
        }
        // An image with several tags is listed once, under its first name.
        if (img.ref.isEmpty() && repo != "<none>")
            img.ref = tag.isEmpty() || tag == "<none>" ? repo : repo + ":" + tag;
    }
    for (const QByteArray &raw : containers.split('\n')) {
        const QStringList f = QString::fromUtf8(raw).trimmed().split(' ', Qt::SkipEmptyParts);
        if (f.size() < 3 || !byId.contains(f.at(0)))
            continue;
        const QString name = f.at(2).startsWith('/') ? f.at(2).mid(1) : f.at(2);
        (f.at(1) == "running" ? byId[f.at(0)].running : byId[f.at(0)].stopped) << name;
    }
    QList<Image> out;
    for (const QString &id : order) {
        Image img = byId.value(id);
        if (img.ref.isEmpty())
            img.ref = id.mid(7, 12); // untagged: the short id, as docker shows it
        out << img;
    }
    return out;
}

QString exposureSummary(const Image &img) {
    if (!img.running.isEmpty())
        return "running as container " + img.running.join(", ");
    if (!img.stopped.isEmpty())
        return "not running; stopped container " + img.stopped.join(", ") + " uses it";
    return "no container uses this image";
}

QList<Matcher::Finding> parseTrivy(const QByteArray &json, const Image &img, const Store &store,
                                   const QHash<QString, Feeds::Kev> &kev) {
    QList<Matcher::Finding> out;
    for (const QJsonValue &r : QJsonDocument::fromJson(json).object().value("Results").toArray()) {
        const QJsonObject result = r.toObject();
        for (const QJsonValue &v : result.value("Vulnerabilities").toArray()) {
            const QJsonObject vuln = v.toObject();
            Matcher::Finding f;
            f.layer = "docker";
            f.package = img.ref;
            f.location = img.id;
            f.cve = vuln.value("VulnerabilityID").toString();
            f.component = vuln.value("PkgName").toString();
            f.version = vuln.value("InstalledVersion").toString();
            f.upstream = f.version;
            f.ecosystem = result.value("Type").toString();
            f.fixedIn = vuln.value("FixedVersion").toString().section(',', 0, 0).trimmed();
            f.verdict = "affected";
            f.source = "trivy";
            f.match = "vendor"; // trivy reads the image's own package database
            f.severity = vuln.value("Severity").toString();
            f.score = score(vuln);
            f.title = vuln.value("Title").toString();
            f.description = vuln.value("Description").toString().left(1500);
            f.reason = QString("trivy found %1 %2 in %3").arg(f.component, f.version, result.value("Target").toString());
            if (!f.cve.startsWith("CVE-"))
                f.advisory = f.cve;
            Cve5::Record rec;
            if (f.score < 0 && f.cve.startsWith("CVE-") && store.record(f.cve, &rec))
                f.score = rec.score;
            if (kev.contains(f.cve)) {
                f.kev = true;
                f.kevAdded = kev.value(f.cve).dateAdded;
            }
            // Nothing runs this image, so nothing runs its flawed files.
            if (img.running.isEmpty()) {
                f.applies = "unclear";
                f.priority = "later";
                f.why = img.stopped.isEmpty() ? QString("No container uses this image.")
                                              : QString("No running container uses this image; stopped: %1.")
                                                    .arg(img.stopped.join(", "));
                f.triagedBy = "ward";
            }
            out << f;
        }
    }
    return out;
}

bool listed(const Matcher::Finding &f) { return f.kev || f.severity == "CRITICAL"; }

QJsonObject counts(const QList<Matcher::Finding> &all) {
    QJsonObject c{{"total", int(all.size())}};
    int fixable = 0, exploited = 0;
    for (const Matcher::Finding &f : all) {
        const QString sev = f.severity.isEmpty() ? QString("UNKNOWN") : f.severity;
        c.insert(sev.toLower(), c.value(sev.toLower()).toInt() + 1);
        fixable += !f.fixedIn.isEmpty();
        exploited += f.kev;
    }
    c.insert("fixable", fixable);
    c.insert("exploited", exploited);
    return c;
}

Run check(const QString &cacheDir, const Store &store, const QHash<QString, Feeds::Kev> &kev, bool offline) {
    Run r;
    if (QStandardPaths::findExecutable("docker").isEmpty()) {
        r.error = "Docker isn't installed";
        return r;
    }
    if (QStandardPaths::findExecutable("trivy").isEmpty()) {
        r.error = "trivy isn't installed (sudo pacman -S trivy)";
        return r;
    }
    int code = 0;
    const QByteArray images = run("docker", {"image", "ls", "--no-trunc", "--format", "{{json .}}"}, 60000, &code);
    if (code != 0) {
        r.error = "docker image ls failed (is the Docker daemon running, and are you in the docker group?)";
        return r;
    }
    const QStringList ids = QString::fromUtf8(run("docker", {"ps", "-aq", "--no-trunc"})).split('\n', Qt::SkipEmptyParts);
    const QByteArray containers =
        ids.isEmpty() ? QByteArray()
                      : run("docker", QStringList{"inspect", "--format", "{{.Image}} {{.State.Status}} {{.Name}}"} + ids);
    r.available = true;
    const QString dir = cacheDir + "/trivy";
    QDir().mkpath(dir);
    for (const Image &img : parseImages(images, containers)) {
        ++r.images;
        const QString path = dir + "/" + img.id.mid(7) + ".json";
        const QFileInfo cached(path);
        QByteArray json;
        // trivy's database changes daily; a scan a day old is redone.
        if (cached.exists() && cached.lastModified().secsTo(QDateTime::currentDateTime()) < 86400) {
            QFile f(path);
            if (f.open(QIODevice::ReadOnly))
                json = f.readAll();
            ++r.cached;
        } else {
            QStringList args{"image", "--quiet", "--format", "json", "--scanners", "vuln"};
            if (offline)
                args << "--skip-db-update" << "--offline-scan";
            json = run("trivy", args << img.id, 600000, &code);
            if (code != 0 || json.isEmpty()) {
                r.error = QString("trivy couldn't scan %1").arg(img.ref);
                continue;
            }
            QSaveFile out(path);
            if (out.open(QIODevice::WriteOnly)) {
                out.write(json);
                out.commit();
            }
            ++r.scanned;
        }
        const QList<Matcher::Finding> all = parseTrivy(json, img, store, kev);
        r.found += all.size();
        int shown = 0;
        for (Matcher::Finding f : all) {
            if (!listed(f))
                continue;
            f.description = f.description.left(600);
            r.findings << f;
            ++shown;
        }
        const QJsonObject c = counts(all);
        QString summary = exposureSummary(img);
        if (!all.isEmpty())
            summary += QString("; %1 CVEs in it (%2 critical, %3 high, %4 with a fixed version); listed: the %5 "
                               "critical or exploited")
                           .arg(all.size())
                           .arg(c.value("critical").toInt())
                           .arg(c.value("high").toInt())
                           .arg(c.value("fixable").toInt())
                           .arg(shown);
        r.exposure.insert("docker:" + img.id, QJsonObject{{"summary", summary}, {"counts", c}});
    }
    return r;
}

} // namespace Docker
