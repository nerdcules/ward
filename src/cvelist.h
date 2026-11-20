#pragma once

#include <QDate>
#include <QString>
#include <QTextStream>

class Store;

// Keeps the Store in step with CVE.org's cvelistV5 releases on GitHub:
// - the first time, the baseline (every record at midnight UTC of the latest
//   release's day: 669,188,631 bytes on 2026-11-20). It is read straight from
//   the zip and deleted afterwards;
// - then one "end_of_day" delta for each whole day since, which CVE.org
//   keeps (2025-11-20's was still there on 2026-11-20);
// - then today's newest hourly delta, which holds every change since midnight.
// Progress is recorded in the store's meta table, so an interrupted sync
// carries on where it stopped.
namespace CveList {

const QString kRepo = QStringLiteral("https://github.com/CVEProject/cvelistV5");

QString baselineAsset(const QDate &day);
QString endOfDayUrl(const QDate &day);
QString hourlyUrl(const QDate &day, int hour);

// The release tag of the newest hourly delta, "cve_2026-11-20_1000Z", gives
// its day and hour. Returns false for anything else.
bool parseHourlyTag(const QString &tag, QDate *day, int *hour);

bool sync(Store &store, const QString &cacheDir, QTextStream &log, QString *error);

} // namespace CveList
