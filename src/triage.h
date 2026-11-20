#pragma once

#include "matcher.h"

#include <QJsonObject>
#include <QList>
#include <QString>

// Claude reads one package's findings with the evidence Ward gathered and
// says, for each CVE, whether it applies on this machine and how soon it
// matters. It runs as Fathom's "Ask Claude" does: `claude -p` with no tools,
// no MCP servers, no settings or hooks (`--setting-sources project` in an
// empty folder) and nothing saved, on the user's Claude account. Claude
// runs nothing: Ward works out the fix itself (an update that is already in
// the repos, or none yet); Claude may suggest a mitigation, which is shown,
// never run without the user.
namespace Triage {

const QString kDefaultModel = QStringLiteral("claude-sonnet-5-5");

struct Verdict {
    QString cve, applies, priority, why; // applies: yes|no|unclear; priority: now|soon|later
};

struct Answer {
    QList<Verdict> verdicts;
    QString mitigation; // optional, one command or step
    QString error;
    double costUsd = -1, seconds = 0;
};

// The system prompt, and the question for one package's findings.
QString systemPrompt();
// `findings` are one group's (one package, project, image or device).
QString question(const QList<Matcher::Finding> &findings, const QString &exposure);

// Reads `claude -p --output-format json` output: its "result" must hold the
// JSON object the system prompt asks for (a ```json fence is tolerated).
Answer parse(const QByteArray &claudeOutput);

// Runs Claude; `claude` is the program (WARD_CLAUDE overrides, for tests).
Answer ask(const QString &claude, const QString &model, const QString &question, const QString &workDir);

} // namespace Triage
