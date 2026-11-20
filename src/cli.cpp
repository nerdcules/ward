#include "cli.h"

#include "cve5.h"
#include "cvelist.h"
#include "feeds.h"
#include "inventory.h"
#include "matcher.h"
#include "notifier.h"
#include "paths.h"
#include "schedule.h"
#include "report.h"
#include "review.h"
#include "triage.h"
#include "store.h"
#include "vercmp.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QSet>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QTextStream>
#include <algorithm>

namespace {

void usage(QTextStream &out) {
    out << "ward - which published CVEs affect this machine\n\n"
           "  ward [open]          open the window\n"
           "  ward check [--json] [--offline] [--no-triage] [--notify] [--list] [--all]\n"
           "                       bring the CVE list up to date, match it against what is\n"
           "                       installed, and have Claude triage what is new; one line\n"
           "                       per package. --offline uses the copy already here,\n"
           "                       --no-triage doesn't ask Claude (earlier answers still\n"
           "                       show), --notify sends a desktop alert for what is newly\n"
           "                       urgent, --list shows each CVE, --all also lists matches\n"
           "                       whose versions can't be read\n"
           "  ward update          only bring the CVE list up to date\n"
           "  ward status [--json] [--list] [--all]\n"
           "                       the last check's results, without checking\n"
           "  ward show <CVE-ID>   one CVE: what it says, and why it matched here\n"
           "  ward fix <package>   what would fix a package; Ward prints it, it never runs it\n"
           "  ward schedule on|off|status\n"
           "                       the daily check (a systemd user timer)\n"
           "  ward skill install   install the agent skill into ~/.claude/skills/ward\n\n"
           "Commands exit 0 on success and 1 with the problem on stderr.\n";
}

// Claude calls per check, 25 CVEs of one package each (WARD_TRIAGE_CALLS
// changes the number). What is left waits for the next check, most urgent
// first; answers are kept, so each CVE is asked about once.
const int kDefaultTriageCalls = 10;
const int kTriagePerCall = 25;

QString statePath() { return Paths::state() + "/findings.json"; }

bool update(Store &store, QTextStream &log, QString *error) {
    Feeds::refresh(Paths::cache(), log);
    return CveList::sync(store, Paths::cache(), log, error);
}

// Cut to width - 1 so a long value never runs into the next column.
QString pad(const QString &s, int width) { return s.leftJustified(width - 1, ' ', true) + ' '; }

void printFindings(QTextStream &out, const QJsonObject &state, bool all, bool list) {
    const QJsonArray findings = state.value("findings").toArray();
    const Report::Totals t = Report::totals(findings);
    const int affected = t.affected, unknown = t.unknown, kev = t.kev, now = t.now, soon = t.soon, open = t.open,
              byClaude = t.byClaude, byWard = t.byWard;
    const QList<Report::PackageSummary> packages = Report::byPackage(findings);
    out << "Checked " << state.value("checkedAt").toString() << ": " << state.value("packages").toInt()
        << " packages against " << state.value("records").toInt() << " CVE records.\n";
    out << affected << " CVEs match " << packages.size() << " packages; " << kev
        << " are known to be exploited.\n";
    out << "Triage: " << now << " matter now, " << soon << " soon, " << affected - now - soon - open
        << " later or not at all; " << open << " not looked at yet (" << byClaude << " judged by Claude, "
        << byWard << " settled by Ward from the evidence).\n";
    const QJsonObject run = state.value("triage").toObject();
    if (run.value("calls").toInt() > 0)
        out << "This check asked Claude " << run.value("calls").toInt() << " time"
            << (run.value("calls").toInt() == 1 ? "" : "s") << " (" << run.value("model").toString() << ", "
            << QString::number(run.value("seconds").toDouble(), 'f', 0) << " s, $"
            << QString::number(run.value("costUsd").toDouble(), 'f', 2) << " as Claude Code reported it).\n";
    for (const QJsonValue &e : run.value("errors").toArray())
        out << "  Triage failed: " << e.toString() << "\n";
    out << unknown << " more matched by name with no versions Ward can read"
        << (all ? ".\n" : " (--all lists them).\n");
    for (const QJsonValue &v : state.value("kernels").toArray()) {
        const QJsonObject k = v.toObject();
        if (k.value("eol").toBool())
            out << "\nThe kernel, " << k.value("package").toString() << " " << k.value("version").toString()
                << ", is on the " << k.value("branch").toString()
                << " branch, which kernel.org no longer maintains; the current stable is "
                << k.value("stable").toString() << ".\n";
    }
    if (!packages.isEmpty()) {
        out << "\n"
            << pad("PACKAGE", 22) << pad("INSTALLED", 24) << pad("CVES", 6) << pad("NOW", 5) << pad("SOON", 5)
            << pad("OPEN", 5) << pad("EXPL", 5) << pad("IN REPOS", 16) << "FIXED UPSTREAM IN\n";
        auto n = [](int v) { return v ? QString::number(v) : QString("-"); };
        for (const Report::PackageSummary &s : packages)
            out << pad(s.package, 22) << pad(s.version, 24) << pad(QString::number(s.count), 6) << pad(n(s.now), 5)
                << pad(n(s.soon), 5) << pad(n(s.open), 5) << pad(n(s.kev), 5)
                << pad(s.updateTo.isEmpty() ? "-" : s.updateTo, 16) << (s.fixAll.isEmpty() ? "-" : s.fixAll)
                << "\n";
        out << "\nNOW/SOON: triage's priority; OPEN: not triaged yet. IN REPOS: a fixing update is\n"
               "waiting (omarchy-update installs it). `ward status --list` shows each CVE and why.\n";
    }
    if (!list && !all)
        return;
    out << "\n"
        << pad("CVE", 17) << pad("PACKAGE", 22) << pad("PRIORITY", 9) << pad("APPLIES", 8) << pad("SCORE", 6)
        << "WHY\n";
    for (const QJsonValue &v : findings) {
        const Matcher::Finding f = Matcher::Finding::fromJson(v.toObject());
        if (f.verdict != "affected" && !all)
            continue;
        out << pad(f.cve, 17) << pad(f.package, 22) << pad(f.priority.isEmpty() ? "-" : f.priority, 9)
            << pad(f.applies.isEmpty() ? "-" : f.applies, 8)
            << pad(f.score >= 0 ? QString::number(f.score, 'f', 1) : "-", 6) << (f.kev ? "EXPLOITED " : "")
            << (f.verdict == "unknown" ? "(versions unreadable) " : "")
            << (f.why.isEmpty() ? (f.title.isEmpty() ? f.description.left(90) : f.title.left(90)) : f.why) << "\n";
    }
}

QJsonArray kernels(const QList<Inventory::Package> &packages) {
    const QList<Feeds::KernelBranch> branches = Feeds::parseKernels(Feeds::read(Paths::cache() + "/kernel-releases.json"));
    QString stable;
    for (const Feeds::KernelBranch &b : branches)
        if (b.moniker == "stable" && (stable.isEmpty() || Vercmp::rpmvercmp(b.version, stable) > 0))
            stable = b.version;
    QJsonArray out;
    if (branches.isEmpty())
        return out;
    for (const Inventory::Package &p : packages) {
        if (!p.kernel)
            continue;
        const QString upstream = Vercmp::upstream(p.version);
        bool found = false;
        const Feeds::KernelBranch b = Feeds::kernelBranch(branches, upstream, &found);
        out.append(QJsonObject{{"package", p.name},
                               {"version", p.version},
                               {"branch", upstream.section('.', 0, 1)},
                               {"eol", !found || b.eol},
                               {"stable", stable}});
    }
    return out;
}

// Announces what is newly urgent and remembers it in notified.json, so each
// finding is announced once.
void notify(const QJsonObject &state, QTextStream &log) {
    const QString path = Paths::state() + "/notified.json";
    QSet<QString> notified;
    for (const QJsonValue &v : QJsonDocument::fromJson(Feeds::read(path)).array())
        notified.insert(v.toString());
    const QList<Notifier::Alert> due =
        Notifier::due(state.value("findings").toArray(), state.value("kernels").toArray(), notified);
    if (due.isEmpty())
        return;
    QStringList lines;
    for (const Notifier::Alert &a : due.mid(0, 5))
        lines << a.line;
    if (due.size() > 5)
        lines << QCoreApplication::translate("Notifier", "and %n more", "", int(due.size() - 5));
    QString error;
    if (!Notifier::send(Notifier::headline(int(due.size())), lines.join('\n'), &error)) {
        log << "Could not send the alert: " << error << "\n";
        return;
    }
    for (const Notifier::Alert &a : due)
        notified.insert(a.key);
    QJsonArray list;
    for (const QString &k : notified)
        list.append(k);
    QSaveFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(list).toJson(QJsonDocument::Compact));
        file.commit();
    }
}

int fix(const QString &package, QTextStream &out, QTextStream &err) {
    const QJsonObject state = QJsonDocument::fromJson(Feeds::read(statePath())).object();
    for (const Report::PackageSummary &s : Report::byPackage(state.value("findings").toArray())) {
        if (s.package != package)
            continue;
        out << s.package << " " << s.version << ": " << s.count << " CVEs.\n";
        if (!s.updateTo.isEmpty())
            out << "A fixing update is waiting in the repos (" << s.updateTo << "). Install it with:\n  omarchy-update\n";
        else
            out << "No fixed package is in the repos yet"
                << (s.fixAll.isEmpty() ? QString(".") : " (fixed upstream in " + s.fixAll + ").") << "\n";
        const QString m = Report::mitigation(QJsonDocument::fromJson(Feeds::read(Paths::state() + "/triage.json")).object(),
                                             s.package, s.version);
        if (!m.isEmpty())
            out << "Claude's suggested mitigation until then (check it before running it):\n  " << m << "\n";
        return 0;
    }
    err << package << " has no findings in the last check.\n";
    return 1;
}

int installSkill(QTextStream &out, QTextStream &err) {
    QFile source(":/skill/SKILL.md");
    if (!source.open(QIODevice::ReadOnly)) {
        err << "The bundled skill is missing from this build.\n";
        return 1;
    }
    const QString directory = QDir::homePath() + "/.claude/skills/ward";
    QSaveFile target(directory + "/SKILL.md");
    if (!QDir().mkpath(directory) || !target.open(QIODevice::WriteOnly) || target.write(source.readAll()) < 0 ||
        !target.commit()) {
        err << "Could not write " << directory << "/SKILL.md\n";
        return 1;
    }
    out << "Installed " << directory << "/SKILL.md\n";
    return 0;
}

int schedule(const QString &what, QTextStream &out, QTextStream &err) {
    if (what.isEmpty() || what == "status") {
        const Schedule::State st = Schedule::state();
        out << (st == Schedule::State::On ? "on" : st == Schedule::State::Off ? "off" : "not installed") << "\n";
        return 0;
    }
    if (what != "on" && what != "off") {
        err << "Usage: ward schedule on|off|status\n";
        return 1;
    }
    QString error;
    if (!Schedule::set(what == "on", &error)) {
        err << error << "\n";
        return 1;
    }
    out << "Daily check " << what << "\n";
    return 0;
}

int check(const QStringList &args, QTextStream &out, QTextStream &err) {
    const bool json = args.contains("--json"), offline = args.contains("--offline"), all = args.contains("--all");
    QTextStream &log = json ? err : out;
    Store store(Paths::cache() + "/cve.sqlite");
    QString error;
    if (!store.open(&error)) {
        err << "Could not open the CVE list: " << error << "\n";
        return 1;
    }
    if (store.wasReset())
        log << "Ward's CVE list is from an older version of Ward; it will be downloaded again.\n";
    if (!offline && !update(store, log, &error)) {
        err << "Could not update the CVE list: " << error << "\n";
        return 1;
    }
    if (store.meta("baseline").isEmpty()) {
        err << "There is no CVE list yet; run `ward update` with the network on.\n";
        return 1;
    }
    const QList<Inventory::Package> packages = Inventory::packages(&error);
    if (packages.isEmpty()) {
        err << "Could not list the installed packages: " << error << "\n";
        return 1;
    }
    const Matcher::Names names =
        Matcher::loadNames(Feeds::read(":/names.json"), Feeds::read(Paths::config() + "/names.json"));
    QElapsedTimer timer;
    timer.start();
    QList<Matcher::Finding> findings =
        Matcher::run(packages, Feeds::parseArch(Feeds::read(Paths::cache() + "/arch-all.json")),
                     Feeds::parseKev(Feeds::read(Paths::cache() + "/kev.json")), store, names);
    const qint64 matchMs = timer.elapsed();

    // What this machine uses, and what the repos already have.
    const QJsonObject exposure = Review::addExposure(findings, packages);
    QHash<QString, QString> pending;
    if (!offline) {
        QString e;
        pending = Review::pendingUpdates(&e);
        if (!e.isEmpty())
            log << "Could not look for waiting updates: " << e << "\n";
    }
    Review::addUpdates(findings, pending);

    // Claude's triage of what Ward couldn't settle.
    const QString cachePath = Paths::state() + "/triage.json";
    const QString model = qEnvironmentVariable("WARD_TRIAGE_MODEL", Triage::kDefaultModel);
    QJsonObject triageState{{"model", model}};
    if (args.contains("--no-triage")) {
        Review::applyCache(findings, cachePath);
        triageState.insert("skipped", true);
    } else {
        bool ok = false;
        int maxCalls = qEnvironmentVariableIntValue("WARD_TRIAGE_CALLS", &ok);
        if (!ok)
            maxCalls = kDefaultTriageCalls;
        const Review::TriageRun run =
            Review::triage(findings, exposure, cachePath, qEnvironmentVariable("WARD_CLAUDE", "claude"), model,
                           maxCalls, kTriagePerCall, log);
        triageState = QJsonObject{{"model", model},
                                  {"calls", run.calls},
                                  {"triaged", run.triaged},
                                  {"cached", run.cached},
                                  {"left", run.left},
                                  {"failed", run.failed},
                                  {"costUsd", run.costUsd},
                                  {"seconds", run.seconds},
                                  {"errors", QJsonArray::fromStringList(run.errors)}};
    }
    Matcher::sort(findings);

    QJsonArray list;
    for (const Matcher::Finding &f : findings)
        list.append(f.toJson());
    const QJsonObject state{{"checkedAt", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
                            {"packages", packages.size()},
                            {"records", store.records()},
                            {"cveListThrough", store.meta("hour").isEmpty() ? store.meta("days_through")
                                                                            : store.meta("hour")},
                            {"matchMilliseconds", matchMs},
                            {"kernels", kernels(packages)},
                            {"exposure", exposure},
                            {"triage", triageState},
                            {"findings", list}};
    QSaveFile file(statePath());
    if (!file.open(QIODevice::WriteOnly) || file.write(QJsonDocument(state).toJson()) < 0 || !file.commit()) {
        err << "Could not save " << statePath() << "\n";
        return 1;
    }
    if (args.contains("--notify"))
        notify(state, log);
    if (json)
        out << QJsonDocument(state).toJson();
    else
        printFindings(out, state, all, args.contains("--list"));
    return 0;
}

int status(const QStringList &args, QTextStream &out, QTextStream &err) {
    QFile file(statePath());
    if (!file.open(QIODevice::ReadOnly)) {
        err << "No check has run yet; run `ward check`.\n";
        return 1;
    }
    const QByteArray data = file.readAll();
    if (args.contains("--json"))
        out << data;
    else
        printFindings(out, QJsonDocument::fromJson(data).object(), args.contains("--all"), args.contains("--list"));
    return 0;
}

int show(const QString &id, QTextStream &out, QTextStream &err) {
    const QString cve = id.section('@', 0, 0).toUpper();
    Store store(Paths::cache() + "/cve.sqlite");
    QString error;
    Cve5::Record r;
    if (!store.open(&error) || !store.record(cve, &r)) {
        err << cve << " is not in Ward's CVE list.\n";
        return 1;
    }
    out << r.id << (r.title.isEmpty() ? "" : "  " + r.title) << "\n"
        << "Published " << r.published.left(10) << ", updated " << r.updated.left(10)
        << (r.score >= 0 ? QString(", score %1 %2").arg(r.score).arg(r.severity) : QString()) << "\n\n"
        << r.description << "\n\nProducts it names:\n";
    for (const Cve5::Affected &a : r.affected) {
        out << "  [" << a.source << "] " << a.vendor << " / " << a.product
            << (a.defaultStatus.isEmpty() ? "" : " (default " + a.defaultStatus + ")") << "\n";
        for (const Cve5::Range &v : a.versions)
            out << "      " << v.status << " " << v.version
                << (v.lessThan.isEmpty() ? "" : " < " + v.lessThan)
                << (v.lessThanOrEqual.isEmpty() ? "" : " <= " + v.lessThanOrEqual) << "\n";
    }
    QFile file(statePath());
    if (file.open(QIODevice::ReadOnly)) {
        for (const QJsonValue &v : QJsonDocument::fromJson(file.readAll()).object().value("findings").toArray()) {
            const Matcher::Finding f = Matcher::Finding::fromJson(v.toObject());
            if (f.cve == cve)
                out << "\nOn this machine: " << f.package << " " << f.version << ", " << f.verdict << " ("
                    << f.reason << "), matched by " << f.match << " from " << f.source
                    << (f.fixedIn.isEmpty() ? "" : ", fixed in " + f.fixedIn) << (f.kev ? ", EXPLOITED" : "")
                    << "\n"
                    << (f.where.isEmpty() ? QString() : "Kernel code: " + f.where + "\n")
                    << (f.applies.isEmpty() ? QString("Not triaged yet.\n")
                                            : QString("Triage (%1): applies %2, priority %3. %4\n")
                                                  .arg(f.triagedBy, f.applies, f.priority, f.why))
                    << (f.updateTo.isEmpty() ? QString() : "Waiting in the repos: " + f.updateTo + "\n");
        }
    }
    return 0;
}

} // namespace

bool isCliCommand(const QStringList &arguments) {
    static const QStringList commands{"check", "update", "status", "show", "fix", "schedule", "skill",
                                      "help", "--help", "-h", "--version", "-v"};
    return arguments.size() > 1 && commands.contains(arguments.at(1));
}

int runCli(const QStringList &arguments) {
    QTextStream out(stdout), err(stderr);
    const QString command = arguments.value(1);
    const QStringList rest = arguments.mid(2);
    if (command == "check")
        return check(rest, out, err);
    if (command == "update") {
        Store store(Paths::cache() + "/cve.sqlite");
        QString error;
        if (!store.open(&error) || !update(store, out, &error)) {
            err << "Could not update the CVE list: " << error << "\n";
            return 1;
        }
        out << store.records() << " CVE records, through "
            << (store.meta("hour").isEmpty() ? store.meta("days_through") : store.meta("hour")) << ".\n";
        return 0;
    }
    if (command == "status")
        return status(rest, out, err);
    if (command == "show" && !rest.isEmpty())
        return show(rest.first(), out, err);
    if (command == "fix" && !rest.isEmpty())
        return fix(rest.first(), out, err);
    if (command == "schedule")
        return schedule(rest.value(0), out, err);
    if (command == "skill" && rest.value(0) == "install")
        return installSkill(out, err);
    if (command == "--version" || command == "-v") {
        out << "ward " << QCoreApplication::applicationVersion() << "\n";
        return 0;
    }
    usage(command.isEmpty() || command == "help" || command == "--help" || command == "-h" ? out : err);
    return command.isEmpty() || command == "help" || command == "--help" || command == "-h" ? 0 : 1;
}
