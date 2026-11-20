#include "triage.h"

#include <QDir>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QSysInfo>

namespace Triage {

QString systemPrompt() {
    return QStringLiteral(
        "You triage CVE matches for one Linux machine. A tool matched the installed package against "
        "CVE records by product name and version range; matches can be wrong. For each CVE, decide from "
        "the CVE text and the evidence given:\n"
        "- applies: \"yes\" if the flaw is reachable on this machine as described, \"no\" if the "
        "evidence rules it out (a different product with the same name, a platform, build option or "
        "configuration this machine doesn't have, code that isn't loaded and can't be), \"unclear\" "
        "otherwise. Don't guess yes or no; unclear is fine.\n"
        "- priority: \"now\" for an applying flaw that is remotely reachable, being exploited, or lets "
        "a local user gain root; \"soon\" for other applying flaws; \"later\" for no or unclear.\n"
        "- why: one plain sentence naming the evidence that decided it.\n"
        "Arch packages often carry fixes as patches without changing the version; if the version "
        "string suggests a snapshot or patched build, say the match may be stale rather than yes.\n"
        "Optionally, \"mitigation\": one step that reduces exposure until a fixed package arrives "
        "(stopping an unused service, unloading an unused module), only when clearly safe; else \"\".\n"
        "Answer with only this JSON object and nothing else:\n"
        "{\"verdicts\": [{\"cve\": \"CVE-...\", \"applies\": \"yes|no|unclear\", \"priority\": "
        "\"now|soon|later\", \"why\": \"...\"}], \"mitigation\": \"\"}");
}

QString question(const QString &package, const QString &version, const QString &exposure,
                 const QList<Matcher::Finding> &findings) {
    QString q;
    q += QString("Machine: Omarchy (Arch Linux based), %1, glibc, systemd, PAM; a single-user laptop.\n")
             .arg(QSysInfo::currentCpuArchitecture());
    q += QString("Package: %1 %2\n").arg(package, version);
    q += QString("On this machine: %1\n\n").arg(exposure);
    for (const Matcher::Finding &f : findings) {
        q += QString("%1 (score %2%3, published %4)\n")
                 .arg(f.cve, f.score >= 0 ? QString::number(f.score, 'f', 1) : "none",
                      f.kev ? ", on CISA's list of exploited vulnerabilities" : "", f.published.left(10));
        q += QString("  record: %1 / %2; matched because %3%4\n")
                 .arg(f.vendor.isEmpty() ? "Arch tracker" : f.vendor, f.product.isEmpty() ? package : f.product,
                      f.reason, f.fixedIn.isEmpty() ? "" : "; fixed in " + f.fixedIn);
        if (!f.where.isEmpty())
            q += QString("  kernel code: %1 (%2)\n").arg(f.files.join(", ").left(200), f.where);
        q += "  " + QString(f.title.isEmpty() ? f.description : f.title + ". " + f.description).left(500) + "\n";
    }
    return q;
}

Answer parse(const QByteArray &claudeOutput) {
    Answer a;
    const QJsonObject out = QJsonDocument::fromJson(claudeOutput).object();
    if (out.isEmpty()) {
        a.error = "Claude gave no JSON";
        return a;
    }
    a.costUsd = out.value("total_cost_usd").toDouble(-1);
    QString result = out.value("result").toString().trimmed();
    if (out.value("is_error").toBool() || result.isEmpty()) {
        a.error = result.isEmpty() ? "Claude gave no answer" : result.left(300);
        return a;
    }
    if (result.startsWith("```")) {
        result = result.section('\n', 1);
        result = result.left(result.lastIndexOf("```")).trimmed();
    }
    const QJsonObject answer = QJsonDocument::fromJson(result.toUtf8()).object();
    if (!answer.contains("verdicts")) {
        a.error = "Claude's answer wasn't in the asked shape: " + result.left(200);
        return a;
    }
    static const QStringList applies{"yes", "no", "unclear"}, priorities{"now", "soon", "later"};
    for (const QJsonValue &v : answer.value("verdicts").toArray()) {
        const QJsonObject o = v.toObject();
        Verdict verdict{o.value("cve").toString(), o.value("applies").toString(), o.value("priority").toString(),
                        o.value("why").toString().left(400)};
        if (!verdict.cve.startsWith("CVE-") || !applies.contains(verdict.applies) ||
            !priorities.contains(verdict.priority))
            continue;
        a.verdicts.append(verdict);
    }
    a.mitigation = answer.value("mitigation").toString().left(300);
    return a;
}

Answer ask(const QString &claude, const QString &model, const QString &q, const QString &workDir) {
    QDir().mkpath(workDir);
    QElapsedTimer timer;
    timer.start();
    QProcess p;
    p.setWorkingDirectory(workDir);
    p.start(claude, {"-p", "--model", model, "--tools", "", "--strict-mcp-config", "--setting-sources", "project",
                     "--no-session-persistence", "--system-prompt", systemPrompt(), "--output-format", "json"});
    Answer a;
    if (!p.waitForStarted(10000)) {
        a.error = "Could not start " + claude;
        return a;
    }
    p.write(q.toUtf8());
    p.closeWriteChannel();
    if (!p.waitForFinished(300000)) {
        p.kill();
        a.error = "Claude took longer than 5 minutes";
        return a;
    }
    a = parse(p.readAllStandardOutput());
    if (!a.error.isEmpty() && p.exitCode() != 0)
        a.error += " (exit " + QString::number(p.exitCode()) + ": " +
                   QString::fromUtf8(p.readAllStandardError()).trimmed().left(200) + ")";
    a.seconds = timer.elapsed() / 1000.0;
    return a;
}

} // namespace Triage
