#pragma once

#include <QJsonArray>
#include <QSet>
#include <QString>
#include <QStringList>

// The desktop alert the daily check sends. Only what needs the user:
// findings triaged as "now", findings on CISA's exploited list that triage
// hasn't ruled out, and a kernel on a branch kernel.org no longer maintains.
// Each is announced once (its key goes into notified.json).
namespace Notifier {

struct Alert {
    QString key, line;
};

// What to announce from a check's findings and kernels, leaving out keys in
// `notified`.
QList<Alert> due(const QJsonArray &findings, const QJsonArray &kernels, const QSet<QString> &notified);

QString headline(int count);

// Through omarchy-notification-send with an Open button when Omarchy is
// there, and notify-send otherwise. False with the reason when neither works.
bool send(const QString &headline, const QString &body, QString *error = nullptr);

} // namespace Notifier
