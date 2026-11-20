#include "schedule.h"

#include <QCoreApplication>
#include <QProcess>
#include <QStandardPaths>

namespace Schedule {

State state() {
    const QString systemctl = QStandardPaths::findExecutable("systemctl");
    if (systemctl.isEmpty())
        return State::NotInstalled;
    QProcess p;
    p.start(systemctl, {"--user", "is-enabled", "ward.timer"});
    p.waitForFinished(10000);
    const QString s = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
    if (s.isEmpty() || s == "not-found")
        return State::NotInstalled;
    return s == "enabled" ? State::On : State::Off;
}

bool set(bool on, QString *error) {
    if (state() == State::NotInstalled) {
        if (error)
            *error = QCoreApplication::translate("Schedule", "ward.timer is not installed. Run bin/install, then try again.");
        return false;
    }
    QProcess p;
    p.start(QStandardPaths::findExecutable("systemctl"), {"--user", on ? "enable" : "disable", "--now", "ward.timer"});
    p.waitForFinished(10000);
    if (p.exitCode() != 0) {
        if (error)
            *error = QCoreApplication::translate("Schedule", "systemctl failed: %1")
                         .arg(QString::fromUtf8(p.readAllStandardError()).trimmed());
        return false;
    }
    return true;
}

} // namespace Schedule
