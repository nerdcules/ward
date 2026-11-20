#pragma once

#include <QFileSystemWatcher>
#include <QJsonObject>
#include <QObject>
#include <QProcess>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

// The window's state: the last check's results read from findings.json, a
// check on demand (this same program run as `ward check`, so the window and
// the timer do exactly the same work), the daily timer, and the two actions
// Ward offers, each run in a terminal only after the user confirms: the
// update when a fix is waiting in the repos, and Claude's mitigation.
// The state directory and program are injectable so tests use temp ones.
class Backend : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantList packages READ packages NOTIFY changed)
    Q_PROPERTY(QVariantMap summary READ summary NOTIFY changed)
    Q_PROPERTY(bool attentionOnly READ attentionOnly WRITE setAttentionOnly NOTIFY changed)
    Q_PROPERTY(bool checking READ checking NOTIFY checkingChanged)
    Q_PROPERTY(QString progress READ progress NOTIFY progressChanged)
    Q_PROPERTY(bool scheduled READ scheduled NOTIFY scheduledChanged)
    Q_PROPERTY(bool schedulable READ schedulable NOTIFY scheduledChanged)
    Q_PROPERTY(QString error READ error NOTIFY errorChanged)
    Q_PROPERTY(QString notice READ notice NOTIFY noticeChanged)

public:
    explicit Backend(const QString &stateDirectory = {}, const QString &program = {}, QObject *parent = nullptr);

    QVariantList packages() const;
    QVariantMap summary() const;
    bool attentionOnly() const { return m_attentionOnly; }
    void setAttentionOnly(bool on);
    bool checking() const { return m_check.state() != QProcess::NotRunning; }
    QString progress() const { return m_progress; }
    bool scheduled() const { return m_scheduled; }
    bool schedulable() const { return m_schedulable; }
    QString error() const { return m_error; }
    QString notice() const { return m_notice; }

    // One package's CVEs, most pressing first, and what Ward knows about it.
    Q_INVOKABLE QVariantList findings(const QString &package) const;
    Q_INVOKABLE QVariantMap detail(const QString &package) const;

    Q_INVOKABLE void check();
    // The command a package's fix or mitigation would run, or "" when none.
    Q_INVOKABLE QString updateCommand(const QString &package) const;
    Q_INVOKABLE QString mitigationCommand(const QString &package) const;
    Q_INVOKABLE bool runInTerminal(const QString &command);
    Q_INVOKABLE void openCve(const QString &cve);
    Q_INVOKABLE bool setScheduled(bool on);
    Q_INVOKABLE void reload();

signals:
    void changed();
    void checkingChanged();
    void progressChanged();
    void scheduledChanged();
    void errorChanged();
    void noticeChanged();

private:
    void setError(const QString &error);
    void setNotice(const QString &notice);
    void refreshSchedule();
    void watch();

    QString m_stateDirectory, m_program;
    QJsonObject m_state, m_triageCache;
    bool m_attentionOnly = true;
    QProcess m_check;
    QString m_progress, m_checkErrors;
    QFileSystemWatcher m_watcher;
    QTimer m_debounce, m_noticeTimer;
    QString m_error, m_notice;
    bool m_scheduled = false, m_schedulable = false;
};
