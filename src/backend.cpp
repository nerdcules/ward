#include "backend.h"

#include "matcher.h"
#include "paths.h"
#include "report.h"
#include "schedule.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QStandardPaths>
#include <QUrl>
#include <algorithm>

namespace {

QJsonObject readJson(const QString &path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? QJsonDocument::fromJson(f.readAll()).object() : QJsonObject();
}

int priorityRank(const QString &priority, const QString &applies) {
    if (applies.isEmpty())
        return 2; // not triaged yet: between "soon" and "later"
    return priority == "now" ? 0 : priority == "soon" ? 1 : 3;
}

} // namespace

Backend::Backend(const QString &stateDirectory, const QString &program, QObject *parent)
    : QObject(parent), m_stateDirectory(stateDirectory.isEmpty() ? Paths::state() : stateDirectory),
      m_program(program.isEmpty() ? QCoreApplication::applicationFilePath() : program) {
    m_debounce.setSingleShot(true);
    m_debounce.setInterval(200);
    connect(&m_watcher, &QFileSystemWatcher::fileChanged, this, [this] { m_debounce.start(); });
    connect(&m_watcher, &QFileSystemWatcher::directoryChanged, this, [this] { m_debounce.start(); });
    connect(&m_debounce, &QTimer::timeout, this, &Backend::reload);
    m_noticeTimer.setSingleShot(true);
    m_noticeTimer.setInterval(5000);
    connect(&m_noticeTimer, &QTimer::timeout, this, [this] { setNotice({}); });

    // A check's own lines ("Asking Claude about 12 CVEs in glibc...") are its
    // progress; its errors are kept for when it ends.
    m_check.setProcessChannelMode(QProcess::SeparateChannels);
    connect(&m_check, &QProcess::readyReadStandardOutput, this, [this] {
        const QStringList lines = QString::fromUtf8(m_check.readAllStandardOutput()).split('\n', Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            if (line.startsWith("Checked "))
                break; // the summary has begun; the window shows its own
            m_progress = line.trimmed();
        }
        emit progressChanged();
    });
    connect(&m_check, &QProcess::readyReadStandardError, this,
            [this] { m_checkErrors += QString::fromUtf8(m_check.readAllStandardError()); });
    connect(&m_check, &QProcess::stateChanged, this, [this] { emit checkingChanged(); });
    connect(&m_check, &QProcess::finished, this, [this](int code, QProcess::ExitStatus status) {
        m_progress.clear();
        emit progressChanged();
        reload();
        if (status != QProcess::NormalExit || code != 0)
            setError(m_checkErrors.trimmed().section('\n', -1).isEmpty()
                         ? tr("The check stopped before it finished.")
                         : m_checkErrors.trimmed().section('\n', -1));
        else
            setNotice(tr("Check finished."));
    });

    reload();
    refreshSchedule();
}

void Backend::watch() {
    // A finished check replaces findings.json, so the watch is re-armed each time.
    if (!m_watcher.files().isEmpty())
        m_watcher.removePaths(m_watcher.files());
    if (m_watcher.directories().isEmpty())
        m_watcher.addPath(m_stateDirectory);
    const QString file = m_stateDirectory + "/findings.json";
    if (QFileInfo::exists(file))
        m_watcher.addPath(file);
}

void Backend::reload() {
    m_state = readJson(m_stateDirectory + "/findings.json");
    m_triageCache = readJson(m_stateDirectory + "/triage.json");
    watch();
    emit changed();
}

void Backend::setAttentionOnly(bool on) {
    if (on == m_attentionOnly)
        return;
    m_attentionOnly = on;
    emit changed();
}

QVariantList Backend::packages() const {
    QVariantList out;
    for (const Report::PackageSummary &s : Report::byPackage(m_state.value("findings").toArray())) {
        if (m_attentionOnly && s.rank() == 3)
            continue;
        out.append(QVariantMap{{"group", s.group}, {"layer", s.layer}, {"location", QString(s.location).replace(QDir::homePath(), "~")},
                               {"package", s.package}, {"version", s.version}, {"count", s.count},
                               {"now", s.now},         {"soon", s.soon},       {"open", s.open},
                               {"kev", s.kev},         {"updateTo", s.updateTo}, {"fixAll", s.fixAll},
                               {"kernel", s.kernel},   {"rank", s.rank()}});
    }
    return out;
}

QVariantMap Backend::summary() const {
    const QJsonArray findings = m_state.value("findings").toArray();
    const Report::Totals t = Report::totals(findings);
    QString kernelNote;
    for (const QJsonValue &v : m_state.value("kernels").toArray()) {
        const QJsonObject k = v.toObject();
        if (k.value("eol").toBool())
            kernelNote = tr("The kernel's %1 branch no longer gets fixes from kernel.org; the current stable is %2.")
                             .arg(k.value("branch").toString(), k.value("stable").toString());
    }
    const QJsonObject run = m_state.value("triage").toObject();
    return {{"checked", !m_state.isEmpty()},
            {"checkedAt", QDateTime::fromString(m_state.value("checkedAt").toString(), Qt::ISODate).toLocalTime()},
            {"records", m_state.value("records").toInt()},
            {"installed", m_state.value("packages").toInt()},
            {"affected", t.affected},
            {"packages", t.packages},
            {"projects", t.projects},
            {"images", t.images},
            {"devices", t.devices},
            {"now", t.now},
            {"soon", t.soon},
            {"open", t.open},
            {"kev", t.kev},
            {"byClaude", t.byClaude},
            {"byWard", t.byWard},
            {"kernelNote", kernelNote},
            {"triageCalls", run.value("calls").toInt()},
            {"triageCost", run.value("costUsd").toDouble()}};
}

QVariantList Backend::findings(const QString &group) const {
    QList<Matcher::Finding> list;
    for (const QJsonValue &v : m_state.value("findings").toArray()) {
        const Matcher::Finding f = Matcher::Finding::fromJson(v.toObject());
        if (f.groupKey() == group && f.verdict == "affected")
            list.append(f);
    }
    std::stable_sort(list.begin(), list.end(), [](const Matcher::Finding &a, const Matcher::Finding &b) {
        const int ra = priorityRank(a.priority, a.applies), rb = priorityRank(b.priority, b.applies);
        if (ra != rb)
            return ra < rb;
        if (a.kev != b.kev)
            return a.kev;
        return a.score > b.score;
    });
    QVariantList out;
    for (const Matcher::Finding &f : list)
        out.append(QVariantMap{{"cve", f.cve},
                               {"score", f.score},
                               {"kev", f.kev},
                               {"priority", f.priority},
                               {"applies", f.applies},
                               {"why", f.why},
                               {"triagedBy", f.triagedBy},
                               {"title", f.title.isEmpty() ? f.description.left(240) : f.title},
                               {"fixedIn", f.fixedIn},
                               {"component", f.component},
                               {"version", f.version},
                               {"ecosystem", f.ecosystem},
                               {"advisory", f.advisory},
                               {"where", f.where},
                               {"match", f.match}});
    return out;
}

QVariantMap Backend::detail(const QString &group) const {
    QVariantMap out;
    for (const Report::PackageSummary &s : Report::byPackage(m_state.value("findings").toArray())) {
        if (s.group != group)
            continue;
        out = {{"group", s.group},     {"layer", s.layer},   {"package", s.package},
               {"location", QString(s.location).replace(QDir::homePath(), "~")},
               {"version", s.version}, {"updateTo", s.updateTo}, {"fixAll", s.fixAll},
               {"kernel", s.kernel},   {"count", s.count},
               {"mitigation", Report::mitigation(m_triageCache, s.group, s.version)},
               {"exposure", m_state.value("exposure").toObject().value(group).toObject().value("summary").toString()}};
    }
    return out;
}

void Backend::check() {
    if (checking())
        return;
    setError({});
    m_checkErrors.clear();
    m_progress = tr("Starting…");
    emit progressChanged();
    m_check.start(m_program, {"check"});
}

QString Backend::updateCommand(const QString &group) const {
    const QVariantMap d = detail(group);
    if (d.value("updateTo").toString().isEmpty())
        return {};
    if (d.value("layer").toString() == "firmware")
        return "fwupdmgr update";
    if (d.value("layer").toString() != "system")
        return {};
    return QStandardPaths::findExecutable("omarchy-update").isEmpty() ? "sudo pacman -Syu" : "omarchy-update";
}

QString Backend::mitigationCommand(const QString &group) const {
    return detail(group).value("mitigation").toString();
}

bool Backend::runInTerminal(const QString &command) {
    if (command.trimmed().isEmpty())
        return false;
    const QString script = command + "; status=$?; echo; echo \"" +
                           tr("Finished with status %1. Press Enter to close.").arg("$status") + "\"; read -r _";
    QStringList program;
    const QString xdg = QStandardPaths::findExecutable("xdg-terminal-exec");
    const QString terminal = qEnvironmentVariable("TERMINAL");
    if (!xdg.isEmpty())
        program = {xdg, "bash", "-c", script};
    else if (!terminal.isEmpty() && !QStandardPaths::findExecutable(terminal).isEmpty())
        program = {QStandardPaths::findExecutable(terminal), "-e", "bash", "-c", script};
    else {
        setError(tr("No terminal to run it in: install xdg-terminal-exec or set TERMINAL."));
        return false;
    }
    const QString exe = program.takeFirst();
    if (!QProcess::startDetached(exe, program)) {
        setError(tr("Could not open a terminal for %1.").arg(command));
        return false;
    }
    setNotice(tr("Running in a terminal: %1").arg(command));
    return true;
}

void Backend::openCve(const QString &id) {
    // CVEs on cve.org; an advisory without one (GHSA-…, RUSTSEC-…) on osv.dev.
    QDesktopServices::openUrl(QUrl(id.startsWith("CVE-") ? "https://www.cve.org/CVERecord?id=" + id
                                                         : "https://osv.dev/vulnerability/" + id));
}

void Backend::refreshSchedule() {
    const Schedule::State st = Schedule::state();
    const bool schedulable = st != Schedule::State::NotInstalled, scheduled = st == Schedule::State::On;
    if (schedulable != m_schedulable || scheduled != m_scheduled) {
        m_schedulable = schedulable;
        m_scheduled = scheduled;
        emit scheduledChanged();
    }
}

bool Backend::setScheduled(bool on) {
    QString error;
    const bool ok = Schedule::set(on, &error);
    refreshSchedule();
    if (!ok) {
        setError(error);
        return false;
    }
    setNotice(on ? tr("Daily check on. You will be alerted when something needs you.") : tr("Daily check off."));
    return true;
}

void Backend::setError(const QString &error) {
    if (error == m_error)
        return;
    m_error = error;
    emit errorChanged();
}

void Backend::setNotice(const QString &notice) {
    m_notice = notice;
    emit noticeChanged();
    if (!notice.isEmpty())
        m_noticeTimer.start();
}
