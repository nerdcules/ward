#include "firmware.h"

#include "store.h"

#include <QDateTime>
#include <QTimeZone>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QStandardPaths>

namespace Firmware {

namespace {

QByteArray fwupd(const QStringList &args) {
    QProcess p;
    p.start("fwupdmgr", args);
    if (!p.waitForFinished(120000))
        return {};
    return p.readAllStandardOutput();
}

} // namespace

Run parse(const QByteArray &devices, const QByteArray &updates, const QByteArray &remotes, const Store &store,
          const QHash<QString, Feeds::Kev> &kev) {
    Run run;
    run.available = true;
    run.devices = int(QJsonDocument::fromJson(devices).object().value("Devices").toArray().size());
    for (const QJsonValue &r : QJsonDocument::fromJson(remotes).object().value("Remotes").toArray()) {
        const QJsonObject remote = r.toObject();
        if (remote.value("Id").toString() == "lvfs" && remote.value("Mtime").toInteger() > 0)
            run.metadataDate = QDateTime::fromSecsSinceEpoch(remote.value("Mtime").toInteger(), QTimeZone::UTC)
                                   .toString(Qt::ISODate);
    }
    for (const QJsonValue &v : QJsonDocument::fromJson(updates).object().value("Devices").toArray()) {
        const QJsonObject device = v.toObject();
        const QJsonArray releases = device.value("Releases").toArray();
        if (releases.isEmpty())
            continue;
        ++run.updates;
        // The newest release first, as fwupd lists them.
        const QJsonObject release = releases.at(0).toObject();
        for (const QJsonValue &issue : release.value("Issues").toArray()) {
            const QString cve = issue.toString();
            if (!cve.startsWith("CVE-"))
                continue;
            Matcher::Finding f;
            f.layer = "firmware";
            f.cve = cve;
            f.package = device.value("Name").toString();
            f.location = device.value("DeviceId").toString();
            f.version = device.value("Version").toString();
            f.upstream = f.version;
            f.vendor = device.value("Vendor").toString();
            f.fixedIn = release.value("Version").toString();
            f.updateTo = f.fixedIn;
            f.verdict = "affected";
            f.source = "lvfs";
            f.match = "vendor";
            f.title = release.value("Summary").toString();
            f.reason = QString("the vendor's firmware release %1 lists it as fixed").arg(f.fixedIn);
            Cve5::Record r;
            if (store.record(cve, &r)) {
                f.score = r.score;
                f.severity = r.severity;
                f.published = r.published;
                f.description = r.description;
            }
            if (kev.contains(cve)) {
                f.kev = true;
                f.kevAdded = kev.value(cve).dateAdded;
            }
            run.findings << f;
        }
    }
    return run;
}

Run check(const Store &store, const QHash<QString, Feeds::Kev> &kev) {
    Run run;
    if (QStandardPaths::findExecutable("fwupdmgr").isEmpty()) {
        run.error = "fwupd isn't installed";
        return run;
    }
    const QByteArray devices = fwupd({"get-devices", "--json"});
    if (devices.trimmed().isEmpty()) {
        run.error = "fwupdmgr didn't answer";
        return run;
    }
    return parse(devices, fwupd({"get-updates", "--json"}), fwupd({"get-remotes", "--json"}), store, kev);
}

} // namespace Firmware
