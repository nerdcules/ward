// Unit tests for Ward's matching. Fixtures in tests/fixtures are real records
// as published: CVE-2026-99301 and CVE-2026-98706 from CVE.org (fetched
// 2026-11-20), and three groups from Arch's tracker (all.json, same day).

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>

#include "../src/cve5.h"
#include "../src/backend.h"
#include "../src/cvelist.h"
#include "../src/docker.h"
#include "../src/firmware.h"
#include "../src/osv.h"
#include "../src/projects.h"
#include "../src/notifier.h"
#include "../src/report.h"
#include "../src/translator.h"
#include "../src/exposure.h"
#include "../src/review.h"
#include "../src/triage.h"
#include "../src/feeds.h"
#include "../src/inventory.h"
#include "../src/matcher.h"
#include "../src/store.h"
#include "../src/vercmp.h"

namespace {

QByteArray fixture(const QString &name) {
    QFile f(QStringLiteral(FIXTURES) + "/" + name);
    if (!f.open(QIODevice::ReadOnly))
        qFatal("missing fixture %s", qPrintable(name));
    return f.readAll();
}

Cve5::Record record(const QString &name) { return Cve5::parse(QJsonDocument::fromJson(fixture(name)).object()); }

Cve5::Affected kernelBlock(const Cve5::Record &r) {
    for (const Cve5::Affected &a : r.affected)
        for (const Cve5::Range &v : a.versions)
            if (v.version.contains('.'))
                return a;
    return {};
}

Cve5::Affected product(const QString &vendor, const QString &name, const QList<Cve5::Range> &versions,
                       const QString &defaultStatus = {}) {
    Cve5::Affected a;
    a.vendor = vendor;
    a.product = name;
    a.versions = versions;
    a.defaultStatus = defaultStatus;
    a.source = "cna";
    return a;
}

} // namespace

class WardTests : public QObject {
    Q_OBJECT

private slots:
    // The port must order versions exactly as pacman's own vercmp does.
    void vercmpMatchesPacman() {
        const QList<QPair<QString, QString>> pairs{
            {"1.0", "1.0"},           {"1.0", "1.1"},          {"1.10", "1.9"},          {"10.6p1", "10.6p2"},
            {"7.4rc1", "7.4"},        {"7.4-rc1", "7.4"},      {"1.0a", "1.0"},          {"1.0.a", "1.0"},
            {"1.0", "1.0.1"},         {"1:1.0-1", "2.0-1"},    {"2:9.0.2-2", "9.0.2-2"}, {"1.0-1", "1.0-2"},
            {"1.0-1", "1.0"},         {"1.0", "1.0-2"},        {"001", "1"},             {"1.0..1", "1.0.1"},
            {"1.0~rc1", "1.0"},       {"9.0.1225-1", "9.1.0"}, {"20260916-1", "20251001-3"},
            {"3.54.0-1", "3.54.1"},   {"1.2.0", "1.2.0rc"},    {"1_0", "1.0"},           {"a", "1"},
            {"1.0+git", "1.0"},       {"6.12.117", "7.2.15"},  {"7.2.15", "7.3.2"},      {"0:1.0", "1.0"},
        };
        for (const auto &[a, b] : pairs) {
            QProcess p;
            p.start("vercmp", {a, b});
            QVERIFY(p.waitForFinished());
            const int expected = QString::fromUtf8(p.readAllStandardOutput()).trimmed().toInt();
            const int got = Vercmp::compare(a, b);
            QVERIFY2(got == (expected > 0 ? 1 : expected < 0 ? -1 : 0),
                     qPrintable(QString("%1 vs %2: vercmp %3, ours %4").arg(a, b).arg(expected).arg(got)));
        }
    }

    void upstreamDropsEpochAndRelease() {
        QCOMPARE(Vercmp::upstream("2:9.0.2-2"), QString("9.0.2"));
        QCOMPARE(Vercmp::upstream("10.6p1-2"), QString("10.6p1"));
        QCOMPARE(Vercmp::upstream("7.2.15"), QString("7.2.15"));
    }

    // CVE-2026-99301 names fixes in 6.12.117, 6.18.63, 7.3.2 and 7.4-rc1, and
    // none for 7.2: the 7.2 branch stays affected.
    void kernelRecordWithNoFixForTheBranch() {
        const Cve5::Affected k = kernelBlock(record("CVE-2026-99301.json"));
        QCOMPARE(k.defaultStatus, QString("affected"));
        Cve5::Evaluation e = Cve5::evaluate("7.2.15", k);
        QCOMPARE(e.verdict, Cve5::Verdict::Affected);
        QCOMPARE(e.fixedIn, QString("7.3.2"));
        QCOMPARE(Cve5::evaluate("7.3.2", k).verdict, Cve5::Verdict::Unaffected);
        QCOMPARE(Cve5::evaluate("7.3.1", k).verdict, Cve5::Verdict::Affected);
        QCOMPARE(Cve5::evaluate("6.12.117", k).verdict, Cve5::Verdict::Unaffected);
        QCOMPARE(Cve5::evaluate("6.12.116", k).verdict, Cve5::Verdict::Affected);
        QCOMPARE(Cve5::evaluate("6.8", k).verdict, Cve5::Verdict::Unaffected); // before 6.9
        QCOMPARE(Cve5::evaluate("7.5", k).verdict, Cve5::Verdict::Unaffected); // mainline fixed in 7.4-rc1
    }

    // CVE-2026-98706 was fixed in the 7.2 branch at 7.2.10.
    void kernelRecordFixedInTheBranch() {
        const Cve5::Affected k = kernelBlock(record("CVE-2026-98706.json"));
        QCOMPARE(Cve5::evaluate("7.2.15", k).verdict, Cve5::Verdict::Unaffected);
        const Cve5::Evaluation e = Cve5::evaluate("7.2.9", k);
        QCOMPARE(e.verdict, Cve5::Verdict::Affected);
        QCOMPARE(e.fixedIn, QString("7.2.10"));
    }

    void gitVersionsAreSkipped() {
        const Cve5::Record r = record("CVE-2026-99301.json");
        for (const Cve5::Affected &a : r.affected)
            for (const Cve5::Range &v : a.versions)
                QVERIFY(v.type != "git");
    }

    void rangesAndOperators() {
        const auto upTo = product("sqlite", "sqlite", {{"0", "", "3.54.1", "affected", "semver"}});
        QCOMPARE(Cve5::evaluate("3.54.0", upTo).verdict, Cve5::Verdict::Affected);
        QCOMPARE(Cve5::evaluate("3.54.1", upTo).verdict, Cve5::Verdict::Affected);
        QCOMPARE(Cve5::evaluate("3.54.2", upTo).verdict, Cve5::Verdict::Unaffected);

        const auto below = product("x", "x", {{"1.0.3", "1.2.1", "", "affected", "semver"}});
        QCOMPARE(Cve5::evaluate("1.0.2", below).verdict, Cve5::Verdict::Unaffected);
        const Cve5::Evaluation e = Cve5::evaluate("1.2.0", below);
        QCOMPARE(e.verdict, Cve5::Verdict::Affected);
        QCOMPARE(e.fixedIn, QString("1.2.1"));
        QCOMPARE(Cve5::evaluate("1.2.1", below).verdict, Cve5::Verdict::Unaffected);

        const auto op = product("x", "x", {{"< 2.4.0", "", "", "affected", ""}});
        QCOMPARE(Cve5::evaluate("2.3.9", op).verdict, Cve5::Verdict::Affected);
        QCOMPARE(Cve5::evaluate("2.4.0", op).verdict, Cve5::Verdict::Unaffected);

        const auto vPrefix = product("x", "x", {{"v1.0", "v1.5", "", "affected", ""}});
        QCOMPARE(Cve5::evaluate("1.4", vPrefix).verdict, Cve5::Verdict::Affected);

        const auto exact = product("x", "x", {{"2.0", "", "", "affected", ""}, {"2.1", "", "", "affected", ""}});
        QCOMPARE(Cve5::evaluate("2.1", exact).verdict, Cve5::Verdict::Affected);
        QCOMPARE(Cve5::evaluate("2.2", exact).verdict, Cve5::Verdict::Unaffected);
    }

    // Seen in the first real check: each of these gave a wrong "update to".
    void upstreamOrder() {
        QVERIFY(Cve5::compareUpstream("10.6p1", "10.6p2") < 0);
        QVERIFY(Cve5::compareUpstream("10.6", "10.6p1") < 0);  // OpenSSH's p1 follows 10.6
        QVERIFY(Cve5::compareUpstream("0.9-rc4", "0.9rc5") < 0); // avahi
        QVERIFY(Cve5::compareUpstream("0.9rc5", "0.9") < 0);
        QVERIFY(Cve5::compareUpstream("7.4-rc1", "7.4") < 0);
        QCOMPARE(Cve5::compareUpstream("2.44+r50+g1848099f9", "2.44"), 0); // glibc snapshot
        QVERIFY(Cve5::compareUpstream("2.44+r50+g1848099f9", "2.45") < 0);
        QVERIFY(Cve5::compareUpstream("1.10", "1.9") > 0);
        QVERIFY(!Cve5::usableVersion("65fbec56bc578b6b6ee02a527be70787bbd053b0")); // libjxl's commit
        QVERIFY(!Cve5::usableVersion("1848099f9"));
        QVERIFY(Cve5::usableVersion("20260916"));
        QVERIFY(Cve5::usableVersion("v1.2.3"));
        const auto ssh = product("OpenBSD", "OpenSSH", {{"0", "10.6", "", "affected", ""}});
        QCOMPARE(Cve5::evaluate("10.6p1", ssh).verdict, Cve5::Verdict::Unaffected);
    }

    // CVE-2026-39919 as published: "0 < 10.08.0" with default "affected".
    void defaultDoesNotOverruleBoundedRanges() {
        const auto gs = product("Artifex Software", "Ghostscript", {{"0", "10.08.0", "", "affected", "semver"}}, "affected");
        QCOMPARE(Cve5::evaluate("10.08.0", gs).verdict, Cve5::Verdict::Unaffected);
        QCOMPARE(Cve5::evaluate("10.07.1", gs).verdict, Cve5::Verdict::Affected);
        // An open-ended range still lets the default stand.
        const auto open = product("x", "x", {{"2.7", "*", "", "affected", ""}}, "affected");
        QCOMPARE(Cve5::evaluate("2.44", open).verdict, Cve5::Verdict::Affected);
    }

    void unreadableVersionsAreUnknown() {
        const auto na = product("x", "x", {{"n/a", "", "", "affected", ""}});
        QCOMPARE(Cve5::evaluate("1.0", na).verdict, Cve5::Verdict::Unknown);
        const auto unspecified = product("x", "x", {{"unspecified", "", "*", "affected", ""}});
        QCOMPARE(Cve5::evaluate("1.0", unspecified).verdict, Cve5::Verdict::Unknown);
        QCOMPARE(Cve5::evaluate("1.0", product("x", "x", {}, "affected")).verdict, Cve5::Verdict::Unknown);
    }

    void normalise() {
        QCOMPARE(Cve5::normalise("Linux Kernel"), QString("linux-kernel"));
        QCOMPARE(Cve5::normalise("linux_kernel"), QString("linux-kernel"));
        QCOMPARE(Cve5::normalise(" OpenSSH "), QString("openssh"));
    }

    void hourlyTags() {
        QDate day;
        int hour = -1;
        QVERIFY(CveList::parseHourlyTag("cve_2026-11-20_1000Z", &day, &hour));
        QCOMPARE(day, QDate(2026, 11, 20));
        QCOMPARE(hour, 10);
        QVERIFY(!CveList::parseHourlyTag("cve_2026-11-19_at_end_of_day", &day, &hour));
        QCOMPARE(CveList::hourlyUrl(QDate(2026, 11, 20), 9),
                 QString("https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-11-20_0900Z/"
                         "2026-11-20_delta_CVEs_at_0900Z.zip"));
        QCOMPARE(CveList::endOfDayUrl(QDate(2026, 11, 19)),
                 QString("https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-11-19_at_end_of_day/"
                         "2026-11-19_delta_CVEs_at_end_of_day.zip"));
    }

    void storeKeepsTheNewerCopy() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QString error;
        QVERIFY2(store.open(&error), qPrintable(error));
        Cve5::Record r = record("CVE-2026-99301.json");
        QVERIFY(store.put(r));
        Cve5::Record older = r;
        older.updated = "2000-01-01T00:00:00.000Z";
        older.title = "stale";
        QVERIFY(store.put(older));
        Cve5::Record back;
        QVERIFY(store.record("CVE-2026-99301", &back));
        QCOMPARE(back.title, r.title);
        QVERIFY(!store.rows({"linux"}).isEmpty());

        Cve5::Record rejected = r;
        rejected.state = "REJECTED";
        rejected.updated = "2099-01-01T00:00:00.000Z";
        QVERIFY(store.put(rejected));
        QVERIFY(store.rows({"linux"}).isEmpty());
    }

    // A zip as CVE.org ships it: records plus cves/delta.json, a log that
    // parses as JSON but is no record. The first real import stopped on it.
    void importSkipsLogs() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        int count = -1;
        QString error;
        QVERIFY2(store.importZip(QStringLiteral(FIXTURES) + "/records-and-log.zip", &count, &error), qPrintable(error));
        QCOMPARE(count, 1);
        QCOMPARE(store.records(), 1);
    }

    void triageAnswers() {
        const QByteArray ok = fixture("claude-answer.json");
        const Triage::Answer a = Triage::parse(ok);
        QVERIFY2(a.error.isEmpty(), qPrintable(a.error));
        QCOMPARE(a.verdicts.size(), 1); // "maybe" isn't an allowed answer
        QCOMPARE(a.verdicts.first().why, QString("needs musl"));
        QCOMPARE(a.costUsd, 0.012);
        QVERIFY(!Triage::parse("{\"is_error\":true,\"result\":\"Credit balance is too low\"}").error.isEmpty());
        QVERIFY(!Triage::parse("{\"result\":\"I think it applies.\"}").error.isEmpty());
        QVERIFY(!Triage::parse("not json").error.isEmpty());
    }

    void kernelCodeLocations() {
        QTemporaryDir dir;
        const QString root = dir.filePath("modules"), release = "7.2.15-1-omarchy";
        QDir().mkpath(root + "/" + release);
        auto write = [](const QString &path, const QByteArray &text) {
            QFile f(path);
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write(text);
        };
        write(root + "/" + release + "/pkgbase", "linux-omarchy\n");
        write(root + "/" + release + "/modules.dep",
              "kernel/drivers/net/virtio_net.ko.zst: kernel/drivers/net/net_failover.ko.zst\n"
              "kernel/drivers/net/net_failover.ko.zst:\n"
              "kernel/net/mac80211/mac80211.ko.zst: kernel/net/wireless/cfg80211.ko.zst\n"
              "kernel/drivers/gpu/drm/amd/amdgpu/amdgpu.ko.zst:\n");
        write(root + "/" + release + "/modules.builtin", "kernel/mm/zsmalloc.ko\n");
        write(dir.filePath("proc-modules"), "mac80211 1 0 - Live 0x0\ncfg80211 1 0 - Live 0x0\n");
        const Exposure::Kernel k = Exposure::readKernel("linux-omarchy", root, dir.filePath("proc-modules"), release);
        QVERIFY(k.running);
        QCOMPARE(Exposure::kernelWhere(k, QString("drivers/net/virtio_net.c")), QString("not-loaded"));
        QCOMPARE(Exposure::kernelWhere(k, QString("net/mac80211/sta_info.c")), QString("loaded"));
        QCOMPARE(Exposure::kernelWhere(k, QString("drivers/gpu/drm/amd/amdgpu/amdgpu_vm.c")), QString("not-loaded"));
        QCOMPARE(Exposure::kernelWhere(k, QString("drivers/s390/char/vmcp.c")), QString("other-arch"));
        QCOMPARE(Exposure::kernelWhere(k, QString("arch/arm64/kvm/mmu.c")), QString("other-arch"));
        QCOMPARE(Exposure::kernelWhere(k, QString("mm/zsmalloc.c")), QString("built-in"));
        QCOMPARE(Exposure::kernelWhere(k, QString("kernel/sched/core.c")), QString("core"));
        QCOMPARE(Exposure::kernelWhere(k, QString("drivers/net/loopback.c")), QString("unclear"));
        // The most exposed of a CVE's files decides.
        QCOMPARE(Exposure::kernelWhere(k, QStringList{"drivers/s390/char/vmcp.c", "net/mac80211/rx.c"}),
                 QString("loaded"));
        const Exposure::Kernel other = Exposure::readKernel("linux-omarchy", root, dir.filePath("proc-modules"), "6.18.64-1-lts");
        QVERIFY(!other.running);
    }

    // A stand-in for Claude Code: answers "no" for every CVE it is asked
    // about and counts its calls, as `claude -p --output-format json` would.
    void triageAsksOnceAndKeepsTheAnswer() {
        QTemporaryDir dir;
        const QString stub = QStringLiteral(FIXTURES) + "/claude-stub.sh", calls = dir.filePath("calls");
        qputenv("WARD_STUB_CALLS", calls.toUtf8());
        QList<Matcher::Finding> findings;
        for (int i = 0; i < 30; ++i) {
            Matcher::Finding f;
            f.cve = QString("CVE-2026-%1").arg(1000 + i);
            f.package = i < 27 ? "ffmpeg" : "git";
            f.version = "1.0-1";
            f.verdict = "affected";
            f.score = i;
            findings << f;
        }
        const QString cache = dir.filePath("triage.json");
        QString logText;
        QTextStream log(&logText);
        Review::TriageRun run = Review::triage(findings, {}, cache, stub, "test-model", 2, 25, log);
        // Two calls allowed: ffmpeg's 25 most urgent, then git's 3 (git's top score 29 beats ffmpeg's 26).
        QCOMPARE(run.calls, 2);
        QCOMPARE(run.triaged, 28);
        QCOMPARE(run.left, 2);
        QVERIFY2(run.errors.isEmpty(), qPrintable(run.errors.join("; ")));
        QCOMPARE(findings.at(29).applies, QString("no"));
        QCOMPARE(findings.at(29).triagedBy, QString("claude"));

        // Next check: the 28 come from the cache, one call for the 2 left.
        for (auto &f : findings) {
            f.applies.clear();
            f.triagedBy.clear();
        }
        run = Review::triage(findings, {}, cache, stub, "test-model", 5, 25, log);
        QCOMPARE(run.cached, 28);
        QCOMPARE(run.calls, 1);
        QCOMPARE(run.left, 0);
        QFile c(calls);
        QVERIFY(c.open(QIODevice::ReadOnly));
        QCOMPARE(c.readAll().count('\n'), 3);

        // lib32-git at the same upstream version takes git's answers: no call.
        QList<Matcher::Finding> lib32;
        for (const auto &f : findings)
            if (f.package == "git") {
                Matcher::Finding l = f;
                l.package = "lib32-git";
                l.version = "1.0-2";
                l.applies.clear();
                lib32 << l;
            }
        run = Review::triage(lib32, {}, cache, stub, "test-model", 5, 25, log);
        QCOMPARE(run.calls, 0);
        QCOMPARE(run.cached, 3);
    }

    // A small findings.json as `ward check` writes it.
    static QJsonObject sampleState() {
        auto finding = [](const QString &cve, const QString &pkg, const QString &priority, const QString &applies,
                          bool kev, const QString &updateTo = {}) {
            Matcher::Finding f;
            f.cve = cve;
            f.package = pkg;
            f.version = "1.0-1";
            f.verdict = "affected";
            f.priority = priority;
            f.applies = applies;
            f.kev = kev;
            f.updateTo = updateTo;
            f.score = 7.5;
            if (!applies.isEmpty())
                f.triagedBy = "claude";
            return f.toJson();
        };
        QJsonArray findings{finding("CVE-1", "openssh", "now", "yes", false, "10.7p1-1"),
                            finding("CVE-2", "openssh", "later", "no", true),
                            finding("CVE-3", "ffmpeg", "", "", false),
                            finding("CVE-4", "gpm", "later", "no", false)};
        QJsonArray kernels{QJsonObject{{"package", "linux-omarchy"}, {"version", "7.2.15-1"}, {"branch", "7.2"},
                                       {"eol", true}, {"stable", "7.3.5"}}};
        return {{"checkedAt", "2026-11-20T12:00:00Z"}, {"packages", 1212}, {"records", 429720},
                {"findings", findings}, {"kernels", kernels},
                {"exposure", QJsonObject{{"openssh", QJsonObject{{"summary", "running: ssh"}}}}}};
    }

    void packageSummaries() {
        const auto list = Report::byPackage(sampleState().value("findings").toArray());
        QCOMPARE(list.size(), 3);
        QCOMPARE(list.at(0).package, QString("openssh")); // has a "now"
        QCOMPARE(list.at(0).now, 1);
        QCOMPARE(list.at(0).kev, 1);
        QCOMPARE(list.at(0).updateTo, QString("10.7p1-1"));
        QCOMPARE(list.at(1).package, QString("ffmpeg"));  // untriaged before dismissed
        QCOMPARE(list.at(2).package, QString("gpm"));
        const auto t = Report::totals(sampleState().value("findings").toArray());
        QCOMPARE(t.now, 1);
        QCOMPARE(t.open, 1);
        QCOMPARE(t.kev, 1);
    }

    // "now" findings, and exploited ones not ruled out, are announced once;
    // an exploited CVE triage said doesn't apply is not.
    void alertsAreDueOnce() {
        const QJsonObject s = sampleState();
        auto due = Notifier::due(s.value("findings").toArray(), s.value("kernels").toArray(), {});
        QStringList keys;
        for (const auto &a : due)
            keys << a.key;
        QCOMPARE(keys, QStringList({"kernel-eol@linux-omarchy@7.2", "CVE-1@openssh"}));
        due = Notifier::due(s.value("findings").toArray(), s.value("kernels").toArray(),
                            QSet<QString>{"kernel-eol@linux-omarchy@7.2", "CVE-1@openssh"});
        QVERIFY(due.isEmpty());
    }

    // 217 exploited CVEs in images nothing ran, settled as "later" by Ward,
    // would each have alerted on 20 Nov 2026; untriaged ones still do.
    void exploitedButLaterDoesNotAlert() {
        Matcher::Finding later;
        later.cve = "CVE-9";
        later.package = "python:3.8-bookworm";
        later.layer = "docker";
        later.location = "sha256:abc";
        later.component = "openssl";
        later.version = "1";
        later.verdict = "affected";
        later.kev = true;
        later.applies = "unclear";
        later.priority = "later";
        later.triagedBy = "ward";
        Matcher::Finding open = later;
        open.cve = "CVE-10";
        open.applies.clear();
        open.priority.clear();
        const auto due = Notifier::due(QJsonArray{later.toJson(), open.toJson()}, {}, {});
        QCOMPARE(due.size(), 1);
        QCOMPARE(due.first().key, open.id());
    }

    void dockerListsOnlyCriticalOrExploited() {
        auto f = [](const QString &sev, bool kev, const QString &fixed) {
            Matcher::Finding x;
            x.severity = sev;
            x.kev = kev;
            x.fixedIn = fixed;
            return x;
        };
        const QList<Matcher::Finding> all{f("CRITICAL", false, "1"), f("HIGH", true, ""), f("HIGH", false, "2"),
                                          f("LOW", false, ""), f("", false, "")};
        int listed = 0;
        for (const auto &x : all)
            listed += Docker::listed(x);
        QCOMPARE(listed, 2);
        const QJsonObject c = Docker::counts(all);
        QCOMPARE(c.value("total").toInt(), 5);
        QCOMPARE(c.value("critical").toInt(), 1);
        QCOMPARE(c.value("high").toInt(), 2);
        QCOMPARE(c.value("unknown").toInt(), 1);
        QCOMPARE(c.value("fixable").toInt(), 2);
        QCOMPARE(c.value("exploited").toInt(), 1);
    }

    void windowBackendReadsTheLastCheck() {
        QTemporaryDir dir;
        {
            QFile f(dir.filePath("findings.json"));
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write(QJsonDocument(sampleState()).toJson());
            QFile c(dir.filePath("triage.json"));
            QVERIFY(c.open(QIODevice::WriteOnly));
            c.write(R"({"mitigation@openssh@1.0-1": "sudo systemctl disable --now sshd"})");
        }
        Backend backend(dir.path(), "/bin/false");
        // Needs a look: openssh (now) and ffmpeg (untriaged), not gpm.
        QCOMPARE(backend.packages().size(), 2);
        backend.setAttentionOnly(false);
        QCOMPARE(backend.packages().size(), 3);
        QCOMPARE(backend.summary().value("now").toInt(), 1);
        QVERIFY(backend.summary().value("kernelNote").toString().contains("7.2"));
        const QVariantMap d = backend.detail("openssh");
        QCOMPARE(d.value("exposure").toString(), QString("running: ssh"));
        QCOMPARE(d.value("mitigation").toString(), QString("sudo systemctl disable --now sshd"));
        QVERIFY(!backend.updateCommand("openssh").isEmpty());
        QVERIFY(backend.updateCommand("gpm").isEmpty()); // nothing waiting in the repos
        const QVariantList cves = backend.findings("openssh");
        QCOMPARE(cves.size(), 2);
        QCOMPARE(cves.first().toMap().value("cve").toString(), QString("CVE-1")); // "now" first
    }

    void translatorFollowsTheLanguageFile() {
        QTemporaryDir dir;
        QFile f(dir.filePath("language"));
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("da\n");
        f.close();
        Translator translator(dir.filePath("language"), ":/i18n");
        QCOMPARE(translator.language(), QString("da"));
        QCOMPARE(translator.translate("Main", "Not checked yet"), QString("Ikke tjekket endnu"));
        QCOMPARE(translator.translate("Notifier", "%n security findings need you", nullptr, 2),
                 QString("%n sikkerhedsfund kræver dig"));
    }

    // Every qsTr()/tr()/translate() in the sources has a Danish line, so a
    // new string cannot ship untranslated by accident.
    void danishCatalogCoversEveryString() {
        QFile catalog(":/i18n/da.json");
        QVERIFY(catalog.open(QIODevice::ReadOnly));
        const QJsonObject da = QJsonDocument::fromJson(catalog.readAll()).object();
        const QRegularExpression call("(?:qsTr|tr|translate\\(\"[A-Za-z]+\",)\\s*\\(?\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        QStringList missing;
        int seen = 0;
        QDir src(QFileInfo(__FILE__).absolutePath() + "/../src");
        for (const QString &name : src.entryList({"*.qml", "*.cpp"}, QDir::Files)) {
            QFile file(src.filePath(name));
            QVERIFY(file.open(QIODevice::ReadOnly));
            auto it = call.globalMatch(QString::fromUtf8(file.readAll()));
            while (it.hasNext()) {
                const QString key = it.next().captured(1).replace("\\\"", "\"").replace("\\n", "\n");
                ++seen;
                if (!da.contains(key) && !missing.contains(key))
                    missing.append(key);
            }
        }
        QVERIFY(seen > 50);
        QVERIFY2(missing.isEmpty(), qPrintable("untranslated: " + missing.join(" | ")));
    }

    // ------------------------------------------------ step 3: other layers

    // Made-up lockfiles in each tool's own format.
    void projectLockfiles() {
        const QByteArray npm = R"({"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/undici": {"version": "7.25.0"},
            "node_modules/a/node_modules/@scope/b": {"version": "2.0.0", "dev": true},
            "node_modules/local": {"resolved": "../local", "link": true},
            "packages/x": {"name": "x", "version": "0.1.0"}}})";
        auto deps = Projects::parseNpmLock(npm, "/p", "/p/package-lock.json");
        QStringList got;
        for (const auto &d : deps)
            got << d.name + "@" + d.version + (d.dev ? " dev" : "");
        got.sort();
        QCOMPARE(got, QStringList({"@scope/b@2.0.0 dev", "undici@7.25.0", "x@0.1.0"}));

        const QByteArray v1 = R"({"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": true}}},
            "c": {"version": "file:../c"}}})";
        QCOMPARE(Projects::parseNpmLock(v1, "/p", "f").size(), 2);

        const QByteArray assets = R"({"libraries": {
            "Newtonsoft.Json/13.0.1": {"type": "package"},
            "MyLib/1.0.0": {"type": "project"}}})";
        deps = Projects::parseAssets(assets, "/p", "f");
        QCOMPARE(deps.size(), 1);
        QCOMPARE(deps.first().ecosystem, QString("NuGet"));
        QCOMPARE(deps.first().version, QString("13.0.1"));

        const QString cargo = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n"
                              "[[package]]\nname = \"mine\"\nversion = \"0.1.0\"\n";
        deps = Projects::parseCargoLock(cargo, "/p", "f");
        QCOMPARE(deps.size(), 1); // the path crate isn't in crates.io
        QCOMPARE(deps.first().name, QString("serde"));

        const QString req = "requests==2.31.0\n# comment\nflask>=2\nuvicorn[standard]==0.30.1\n-r other.txt\n";
        deps = Projects::parseRequirements(req, "/p", "f");
        QCOMPARE(deps.size(), 2);
        QCOMPARE(deps.at(1).name, QString("uvicorn"));
    }

    void projectScanSkipsBuildOutput() {
        QTemporaryDir dir;
        auto write = [&](const QString &rel, const QByteArray &text) {
            QDir().mkpath(QFileInfo(dir.filePath(rel)).absolutePath());
            QFile f(dir.filePath(rel));
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write(text);
        };
        const QByteArray lock = R"({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}})";
        write("web/package-lock.json", lock);
        write("web/node_modules/y/package-lock.json", lock);  // inside node_modules
        write("api/Api/obj/project.assets.json", R"({"libraries": {"A/1.0.0": {"type": "package"}}})");
        write("api/out/copy/obj/project.assets.json", R"({"libraries": {"B/1.0.0": {"type": "package"}}})");
        const Projects::Scan scan = Projects::scan({dir.path()});
        QCOMPARE(scan.files.size(), 2);
        QStringList projects;
        for (const auto &d : scan.dependencies)
            projects << QFileInfo(d.project).fileName();
        projects.sort();
        QCOMPARE(projects, QStringList({"Api", "web"})); // obj's owner is the folder above it
    }

    // GHSA-2m5v-pch6-74hx as OSV served it on 20 Nov 2026: undici fixed in
    // 6.29.1, 7.30.1 and 8.12.2, one range per branch.
    void osvAdvisory() {
        const Osv::Advisory a = Osv::parse(QJsonDocument::fromJson(fixture("GHSA-2m5v-pch6-74hx.json")).object());
        QCOMPARE(a.id, QString("GHSA-2m5v-pch6-74hx"));
        QCOMPARE(a.aliases, QStringList({"CVE-2026-109383"}));
        QCOMPARE(a.severity, QString("HIGH"));
        QCOMPARE(Osv::fixedVersion(a, "npm", "undici", "7.25.0"), QString("7.30.1"));
        QCOMPARE(Osv::fixedVersion(a, "npm", "undici", "6.1.0"), QString("6.29.1"));
        QVERIFY(Osv::fixedVersion(a, "npm", "other", "7.25.0").isEmpty());
    }

    void projectFindingsAreKeyedByLocation() {
        Matcher::Finding a;
        a.layer = "project";
        a.cve = "CVE-1";
        a.package = "Foundry.Core";
        a.location = "/home/u/foundry/src/Foundry.Core";
        a.component = "System.Text.Json";
        a.version = "8.0.0";
        Matcher::Finding b = a;
        b.location = "/home/u/foundry-pr33/src/Foundry.Core"; // a copy with the same folder name
        QVERIFY(a.groupKey() != b.groupKey());
        QVERIFY(a.id() != b.id());
        const Matcher::Finding back = Matcher::Finding::fromJson(a.toJson());
        QCOMPARE(back.layer, QString("project"));
        QCOMPARE(back.id(), a.id());
        Matcher::Finding sys;
        sys.cve = "CVE-2";
        sys.package = "openssh";
        QCOMPARE(sys.id(), QString("CVE-2@openssh")); // unchanged, so earlier answers still match
        QCOMPARE(Matcher::Finding::fromJson(sys.toJson()).layer, QString("system"));
        QVERIFY(!sys.toJson().contains("layer"));
    }

    void triageQuestionSaysWhatAProjectIs() {
        Matcher::Finding f;
        f.layer = "project";
        f.cve = "CVE-2026-109383";
        f.advisory = "GHSA-2m5v-pch6-74hx";
        f.package = "web";
        f.location = "/home/u/Projects/web";
        f.component = "undici";
        f.version = "7.25.0";
        f.ecosystem = "npm";
        f.fixedIn = "7.30.1";
        f.reason = "GHSA-2m5v-pch6-74hx lists undici 7.25.0 as affected";
        const QString q = Triage::question({f}, "a project in /home/u/Projects/web");
        QVERIFY(q.contains("dependencies of the software project at /home/u/Projects/web"));
        QVERIFY(q.contains("in: undici 7.25.0 (npm)"));
        QVERIFY(q.contains("record: GHSA-2m5v-pch6-74hx"));
        QVERIFY(q.contains("fixed in 7.30.1"));
        QVERIFY(!q.contains("an Arch package"));
    }

    // Made-up fwupd output in its JSON shape: one device with a release that
    // lists two CVEs, one without.
    void firmwareUpdates() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        const QByteArray devices = R"({"Devices": [{"Name": "System Firmware"}, {"Name": "SSD"}]})";
        const QByteArray updates = R"({"Devices": [
            {"Name": "System Firmware", "DeviceId": "abc", "Vendor": "Example", "Version": "1.10",
             "Releases": [{"Version": "1.12", "Summary": "Security fixes", "Issues": ["CVE-2026-1111", "CVE-2026-2222", "INTEL-SA-1"]}]},
            {"Name": "SSD", "DeviceId": "def", "Version": "2", "Releases": [{"Version": "3", "Issues": []}]}]})";
        const QByteArray remotes = R"({"Remotes": [{"Id": "lvfs", "Mtime": 1793777754}]})";
        const Firmware::Run run = Firmware::parse(devices, updates, remotes, store, {});
        QCOMPARE(run.devices, 2);
        QCOMPARE(run.updates, 2);
        QCOMPARE(run.findings.size(), 2);
        QCOMPARE(run.findings.first().layer, QString("firmware"));
        QCOMPARE(run.findings.first().updateTo, QString("1.12"));
        QCOMPARE(run.metadataDate.left(10), QString("2026-11-04"));
    }

    // Made-up docker and trivy output in their JSON shapes.
    void dockerImages() {
        const QByteArray images =
            "{\"ID\":\"sha256:aaa111\",\"Repository\":\"postgres\",\"Tag\":\"16\"}\n"
            "{\"ID\":\"sha256:aaa111\",\"Repository\":\"pg\",\"Tag\":\"latest\"}\n"
            "{\"ID\":\"sha256:bbb222bbb222bbb\",\"Repository\":\"<none>\",\"Tag\":\"<none>\"}\n";
        const QByteArray containers = "sha256:aaa111 running /db\nsha256:bbb222bbb222bbb exited /old\n";
        const auto list = Docker::parseImages(images, containers);
        QCOMPARE(list.size(), 2);
        QCOMPARE(list.at(0).ref, QString("postgres:16")); // its first name
        QCOMPARE(list.at(0).running, QStringList({"db"}));
        QCOMPARE(list.at(1).ref, QString("bbb222bbb222"));
        QCOMPARE(Docker::exposureSummary(list.at(1)), QString("not running; stopped container old uses it"));

        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        const QByteArray trivy = R"json({"Results": [{"Target": "postgres:16 (debian 12.5)", "Type": "debian",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-3333", "PkgName": "openssl", "InstalledVersion": "3.0.11-1",
                                 "FixedVersion": "3.0.15-1, 3.0.16-1", "Severity": "HIGH", "Title": "t",
                                 "CVSS": {"nvd": {"V3Score": 7.5}}}]}]})json";
        auto running = Docker::parseTrivy(trivy, list.at(0), store, {});
        QCOMPARE(running.size(), 1);
        QCOMPARE(running.first().fixedIn, QString("3.0.15-1"));
        QCOMPARE(running.first().score, 7.5);
        QVERIFY(running.first().applies.isEmpty()); // a running image goes to triage
        auto idle = Docker::parseTrivy(trivy, list.at(1), store, {});
        QCOMPARE(idle.first().applies, QString("unclear"));
        QCOMPARE(idle.first().triagedBy, QString("ward"));
    }

    void archTrackerDecides() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        const auto arch = Feeds::parseArch(fixture("arch-sample.json"));
        QCOMPARE(arch.size(), 3);
        // AVG-2910: php-legacy fixed in 8.3.36-1. AVG-2843: vim fixed in 9.0.1225-1.
        const auto packages = Inventory::parse("php-legacy 8.3.35-2\nvim 9.1.1800-1\n", "", "");
        const auto findings = Matcher::run(packages, arch, {}, store, {});
        QCOMPARE(findings.size(), 2); // AVG-2910 names two CVEs
        for (const auto &f : findings) {
            QCOMPARE(f.package, QString("php-legacy"));
            QCOMPARE(f.fixedIn, QString("8.3.36-1"));
            QCOMPARE(f.match, QString("tracker"));
        }
        const auto fixed = Inventory::parse("php-legacy 8.3.36-1\n", "", "");
        QVERIFY(Matcher::run(fixed, arch, {}, store, {}).isEmpty());
    }

    // A group still "Vulnerable" with no fix, for a version older than the
    // installed one, says nothing about the installed one.
    void staleTrackerGroupsDontDecide() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        Feeds::ArchGroup g{"AVG-1", "Vulnerable", "Critical", "", "1.1.1-1", "", {"openssl"}, {"CVE-2022-2068"}};
        QVERIFY(Matcher::run(Inventory::parse("openssl 3.6.5-1\n", "", ""), {g}, {}, store, {}).isEmpty());
        QCOMPARE(Matcher::run(Inventory::parse("openssl 1.1.1-1\n", "", ""), {g}, {}, store, {}).size(), 1);
    }

    void kernelBranches() {
        const auto branches = Feeds::parseKernels(R"({"releases":[
            {"moniker":"mainline","version":"7.4-rc3","iseol":false},
            {"moniker":"stable","version":"7.3.5","iseol":false},
            {"moniker":"stable","version":"7.2.15","iseol":true},
            {"moniker":"longterm","version":"6.18.64","iseol":false}]})");
        bool found = false;
        QVERIFY(Feeds::kernelBranch(branches, "7.2.15", &found).eol);
        QVERIFY(found);
        QVERIFY(!Feeds::kernelBranch(branches, "6.18.60", &found).eol);
        Feeds::kernelBranch(branches, "6.9.12", &found);
        QVERIFY(!found); // gone from kernel.org's list: also unmaintained
    }

    void foreignPackagesNeedTheVendorInTheirUrl() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        Cve5::Record r;
        r.id = "CVE-2025-12116";
        r.state = "PUBLISHED";
        r.affected = {product("thinkupthemes", "Drift", {{"0", "", "1.5.0", "affected", ""}})};
        QVERIFY(store.put(r));
        Cve5::Record s = r;
        s.id = "CVE-9";
        s.affected = {product("someone", "tool", {{"0", "", "9", "affected", ""}})};
        QVERIFY(store.put(s));
        const QString info = "Name            : drift\nURL             : None\n\n"
                             "Name            : tool\nURL             : https://github.com/someone/tool\n";
        const auto packages = Inventory::parse("drift 0.1.0-1\ntool 1.0-1\n", "drift\ntool\n", "", info);
        const auto findings = Matcher::run(packages, {}, {}, store, {});
        QCOMPARE(findings.size(), 1);
        QCOMPARE(findings.first().id(), QString("CVE-9@tool"));
        QCOMPARE(findings.first().match, QString("vendor"));
    }

    void kernelPackageMatchesLinuxRecords() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        QVERIFY(store.put(record("CVE-2026-99301.json")));
        QVERIFY(store.put(record("CVE-2026-98706.json")));
        const auto packages = Inventory::parse("linux-omarchy 7.2.15-1\nlinux 9.9-1\n", "", "linux-omarchy\n");
        QHash<QString, Feeds::Kev> kev{{"CVE-2026-99301", {"CVE-2026-99301", "2026-11-18", "", ""}}};
        const auto findings = Matcher::run(packages, {}, kev, store, {});
        // Only the kernel package, only the record without a 7.2 fix. The
        // "linux" package here is not a kernel, so it isn't looked up as one,
        // and with vendor Linux's records it has no other match.
        QCOMPARE(findings.size(), 1);
        QCOMPARE(findings.first().cve, QString("CVE-2026-99301"));
        QCOMPARE(findings.first().package, QString("linux-omarchy"));
        QCOMPARE(findings.first().match, QString("vendor"));
        QCOMPARE(findings.first().fixedIn, QString("7.3.2"));
        QVERIFY(findings.first().kev);
    }

    void vendorPinsAndRegistries() {
        QTemporaryDir dir;
        Store store(dir.filePath("cve.sqlite"));
        QVERIFY(store.open(nullptr));
        auto make = [](const QString &id, const QString &vendor, const QString &name, const QString &collection) {
            Cve5::Record r;
            r.id = id;
            r.state = "PUBLISHED";
            r.updated = "2026-11-01T00:00:00Z";
            Cve5::Affected a = product(vendor, name, {{"0", "9.9", "", "affected", "semver"}});
            a.collection = collection;
            r.affected = {a};
            return r;
        };
        QVERIFY(store.put(make("CVE-1", "Microsoft", "python", "")));
        QVERIFY(store.put(make("CVE-2", "Python Software Foundation", "CPython", "")));
        QVERIFY(store.put(make("CVE-3", "someone", "requests", "https://pypi.org")));
        QVERIFY(store.put(make("CVE-4", "someone", "requests", "https://www.npmjs.com")));
        QVERIFY(store.put(make("CVE-5", "someone", "requests", "")));
        const auto names =
            Matcher::loadNames(fixture("../../src/names.json"), R"({"requests": {"vendors": ["nobody"]}})");
        const auto packages = Inventory::parse("python 3.14.8-1\npython-requests 2.32.5-1\n", "", "");
        QStringList ids;
        for (const auto &f : Matcher::run(packages, {}, {}, store, names))
            ids << f.id();
        ids.sort();
        // CVE-1 is Microsoft's (pinned out); CVE-4 is npm's; CVE-5 has no
        // registry, so python-requests looked up as "requests" may take it.
        QCOMPARE(ids, QStringList({"CVE-2@python", "CVE-3@python-requests", "CVE-5@python-requests"}));
    }
};

QTEST_GUILESS_MAIN(WardTests)
#include "ward_tests.moc"
