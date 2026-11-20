#include "notifier.h"

#include "matcher.h"

#include <QCoreApplication>
#include <QJsonObject>
#include <QProcess>
#include <QStandardPaths>

namespace Notifier {

QList<Alert> due(const QJsonArray &findings, const QJsonArray &kernels, const QSet<QString> &notified) {
    QList<Alert> out;
    for (const QJsonValue &v : kernels) {
        const QJsonObject k = v.toObject();
        const QString key = "kernel-eol@" + k.value("package").toString() + "@" + k.value("branch").toString();
        if (k.value("eol").toBool() && !notified.contains(key))
            out.append({key, QCoreApplication::translate("Notifier", "The kernel's %1 branch no longer gets fixes")
                                 .arg(k.value("branch").toString())});
    }
    for (const QJsonValue &v : findings) {
        const Matcher::Finding f = Matcher::Finding::fromJson(v.toObject());
        if (f.verdict != "affected" || notified.contains(f.id()))
            continue;
        // An exploited CVE alerts until triage says otherwise; one already
        // judged or settled as "later" (in an image nothing runs, say) doesn't.
        const bool urgent = f.priority == "now" || (f.kev && f.applies != "no" && f.priority != "later");
        if (!urgent)
            continue;
        out.append({f.id(), f.kev ? QCoreApplication::translate("Notifier", "%1 in %2 (exploited)").arg(f.cve, f.package)
                                  : QCoreApplication::translate("Notifier", "%1 in %2").arg(f.cve, f.package)});
    }
    return out;
}

QString headline(int count) {
    return QCoreApplication::translate("Notifier", "%n security findings need you", "", count);
}

bool send(const QString &headline, const QString &body, QString *error) {
    const QString omarchy = QStandardPaths::findExecutable("omarchy-notification-send");
    if (!omarchy.isEmpty()) {
        QProcess process;
        process.start(omarchy, {"--app-name", "ward", "-i", "ward", "-u", "critical", "--", headline, body,
                                "--action", QCoreApplication::translate("Notifier", "Open"), "ward", "open"});
        if (process.waitForFinished(10000) && process.exitCode() == 0)
            return true;
        if (error)
            *error = QString::fromUtf8(process.readAllStandardError()).trimmed();
    }
    const QString notifySend = QStandardPaths::findExecutable("notify-send");
    if (!notifySend.isEmpty()) {
        QProcess process;
        process.start(notifySend, {"-a", "ward", "-i", "ward", "-u", "critical", "--", headline, body});
        if (process.waitForFinished(10000) && process.exitCode() == 0)
            return true;
        if (error)
            *error = QString::fromUtf8(process.readAllStandardError()).trimmed();
        return false;
    }
    if (error && error->isEmpty())
        *error = QCoreApplication::translate("Notifier", "Neither omarchy-notification-send nor notify-send is installed.");
    return false;
}

} // namespace Notifier
