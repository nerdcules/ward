#pragma once

#include "inventory.h"
#include "matcher.h"

#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QTextStream>

// Step 2 of a check, after matching: what this machine uses, what the
// repos already have, and Claude's triage of what is left.
namespace Review {

// Kernel findings get where their code is (Exposure::kernelWhere); those in
// another architecture's code are settled by Ward as not applying, and those
// in a module that isn't loaded as "later". Returns the package exposure of
// every affected package, keyed by package, for the state file and Claude.
QJsonObject addExposure(QList<Matcher::Finding> &findings, const QList<Inventory::Package> &packages);

// `checkupdates`: package -> the version waiting in the repos. It syncs a
// temporary copy of the package databases, so it needs the network but
// changes nothing on the system. Empty when nothing is waiting.
QHash<QString, QString> pendingUpdates(QString *error);
void addUpdates(QList<Matcher::Finding> &findings, const QHash<QString, QString> &pending);

struct TriageRun {
    int calls = 0, triaged = 0, cached = 0, left = 0, failed = 0;
    double costUsd = 0, seconds = 0;
    QStringList errors;
};

// Triages what isn't settled yet, package by package (up to `perCall` CVEs a
// call, most urgent first), with at most `maxCalls` calls; answers are kept
// in `cachePath` per CVE, package and version, so each is asked once.
TriageRun triage(QList<Matcher::Finding> &findings, const QJsonObject &exposure, const QString &cachePath,
                 const QString &claude, const QString &model, int maxCalls, int perCall, QTextStream &log);

// Applies cached answers only (for `--no-triage`).
void applyCache(QList<Matcher::Finding> &findings, const QString &cachePath);

} // namespace Review
