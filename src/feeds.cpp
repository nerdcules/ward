#include "feeds.h"

#include "net.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace Feeds {

namespace {

QStringList strings(const QJsonValue &v) {
    QStringList out;
    for (const QJsonValue &s : v.toArray())
        out << s.toString();
    return out;
}

} // namespace

QList<ArchGroup> parseArch(const QByteArray &json) {
    QList<ArchGroup> out;
    for (const QJsonValue &v : QJsonDocument::fromJson(json).array()) {
        const QJsonObject o = v.toObject();
        out.append({o.value("name").toString(), o.value("status").toString(), o.value("severity").toString(),
                    o.value("type").toString(), o.value("affected").toString(), o.value("fixed").toString(),
                    strings(o.value("packages")), strings(o.value("issues"))});
    }
    return out;
}

QHash<QString, Kev> parseKev(const QByteArray &json) {
    QHash<QString, Kev> out;
    const QJsonArray list = QJsonDocument::fromJson(json).object().value("vulnerabilities").toArray();
    for (const QJsonValue &v : list) {
        const QJsonObject o = v.toObject();
        const QString id = o.value("cveID").toString();
        out.insert(id, {id, o.value("dateAdded").toString(), o.value("vulnerabilityName").toString(),
                        o.value("knownRansomwareCampaignUse").toString()});
    }
    return out;
}

QList<KernelBranch> parseKernels(const QByteArray &json) {
    QList<KernelBranch> out;
    for (const QJsonValue &v : QJsonDocument::fromJson(json).object().value("releases").toArray()) {
        const QJsonObject o = v.toObject();
        out.append({o.value("moniker").toString(), o.value("version").toString(), o.value("iseol").toBool()});
    }
    return out;
}

KernelBranch kernelBranch(const QList<KernelBranch> &branches, const QString &upstream, bool *found) {
    const QString branch = upstream.section('.', 0, 1);
    for (const KernelBranch &b : branches) {
        if (b.moniker != "stable" && b.moniker != "longterm")
            continue;
        if (b.version == branch || b.version.startsWith(branch + ".")) {
            *found = true;
            return b;
        }
    }
    *found = false;
    return {};
}

QByteArray read(const QString &path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

void refresh(const QString &cacheDir, QTextStream &log) {
    const QList<QPair<QString, QString>> feeds{{kArchUrl, "arch-all.json"}, {kKevUrl, "kev.json"},
                                                    {kKernelUrl, "kernel-releases.json"}};
    for (const auto &[url, name] : feeds) {
        QString error;
        if (!Net::download(QUrl(url), cacheDir + "/" + name, &error))
            log << "Kept the last copy of " << name << ": " << error << "\n";
    }
}

} // namespace Feeds
