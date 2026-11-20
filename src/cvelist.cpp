#include "cvelist.h"

#include "net.h"
#include "store.h"
#include "zip.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace CveList {

namespace {

const QString kLatestApi = QStringLiteral("https://api.github.com/repos/CVEProject/cvelistV5/releases/latest");

QString iso(const QDate &d) { return d.toString(Qt::ISODate); }

bool importBaseline(Store &store, const QString &cacheDir, QTextStream &log, QString *error) {
    QString netError;
    const QByteArray body = Net::get(QUrl(kLatestApi), &netError);
    const QJsonObject release = QJsonDocument::fromJson(body).object();
    QString assetName, assetUrl;
    qint64 assetSize = 0;
    for (const QJsonValue &v : release.value("assets").toArray()) {
        const QJsonObject a = v.toObject();
        if (a.value("name").toString().endsWith("_all_CVEs_at_midnight.zip.zip")) {
            assetName = a.value("name").toString();
            assetUrl = a.value("browser_download_url").toString();
            assetSize = a.value("size").toInteger();
        }
    }
    if (assetName.isEmpty()) {
        if (error)
            *error = "Could not find CVE.org's baseline in its latest release" +
                     (netError.isEmpty() ? QString() : ": " + netError);
        return false;
    }
    const QDate day = QDate::fromString(assetName.left(10), Qt::ISODate);
    const QString outer = cacheDir + "/" + assetName;
    if (QFileInfo(outer).size() != assetSize) {
        log << "Downloading CVE.org's full list, once (" << assetSize / 1000000 << " MB)...\n";
        log.flush();
        if (!Net::download(QUrl(assetUrl), outer, error))
            return false;
    }
    const QString inner = cacheDir + "/cves.zip";
    if (!Zip::extract(outer, "cves.zip", inner, error))
        return false;
    log << "Reading " << assetName << "...\n";
    log.flush();
    QElapsedTimer timer;
    timer.start();
    int count = 0;
    const bool ok = store.importZip(inner, &count, error);
    QFile::remove(inner);
    if (!ok)
        return false;
    QFile::remove(outer);
    store.setMeta("baseline", iso(day));
    store.setMeta("days_through", iso(day.addDays(-1)));
    log << "Read " << count << " records in " << timer.elapsed() / 1000 << " s.\n";
    return true;
}

bool importDelta(Store &store, const QString &url, const QString &cacheDir, int *count, QString *error,
                 int *status) {
    const QString path = cacheDir + "/delta.zip";
    if (!Net::download(QUrl(url), path, error, status))
        return false;
    const bool ok = store.importZip(path, count, error);
    QFile::remove(path);
    return ok;
}

} // namespace

QString baselineAsset(const QDate &day) { return iso(day) + "_all_CVEs_at_midnight.zip.zip"; }

QString endOfDayUrl(const QDate &day) {
    return QString("%1/releases/download/cve_%2_at_end_of_day/%2_delta_CVEs_at_end_of_day.zip").arg(kRepo, iso(day));
}

QString hourlyUrl(const QDate &day, int hour) {
    // Built as "1000Z" first: "%300Z" would be read as placeholder %30.
    const QString stamp = QString("%1").arg(hour, 2, 10, QChar('0')) + "00Z";
    return QString("%1/releases/download/cve_%2_%3/%2_delta_CVEs_at_%3.zip").arg(kRepo, iso(day), stamp);
}

bool parseHourlyTag(const QString &tag, QDate *day, int *hour) {
    static const QRegularExpression pattern(R"(^cve_(\d{4}-\d{2}-\d{2})_(\d{2})00Z$)");
    const auto m = pattern.match(tag);
    if (!m.hasMatch())
        return false;
    *day = QDate::fromString(m.captured(1), Qt::ISODate);
    *hour = m.captured(2).toInt();
    return day->isValid() && *hour < 24;
}

bool sync(Store &store, const QString &cacheDir, QTextStream &log, QString *error) {
    if (store.meta("baseline").isEmpty() && !importBaseline(store, cacheDir, log, error))
        return false;

    // Whole days: each end_of_day delta, oldest first. One that isn't
    // published yet (just after midnight) is left for the next sync.
    const QDate today = QDateTime::currentDateTimeUtc().date();
    QDate through = QDate::fromString(store.meta("days_through"), Qt::ISODate);
    for (QDate day = through.addDays(1); day < today; day = day.addDays(1)) {
        int count = 0, status = 0;
        QString e;
        if (!importDelta(store, endOfDayUrl(day), cacheDir, &count, &e, &status)) {
            if (status == 404) {
                log << "CVE.org's changes for " << iso(day) << " aren't out yet.\n";
                break;
            }
            if (error)
                *error = e;
            return false;
        }
        store.setMeta("days_through", iso(day));
        store.setMeta("hour", QString());
        log << "Applied " << count << " changes from " << iso(day) << ".\n";
    }

    // Today, if the days before it are all in.
    through = QDate::fromString(store.meta("days_through"), Qt::ISODate);
    if (through.addDays(1) != today)
        return true;
    QString e;
    const QString tag = QJsonDocument::fromJson(Net::get(QUrl(kLatestApi), &e)).object().value("tag_name").toString();
    QDate day;
    int hour = 0;
    if (!parseHourlyTag(tag, &day, &hour) || day != today) {
        if (!e.isEmpty())
            log << "Could not look up today's changes: " << e << "\n";
        return true;
    }
    if (store.meta("hour") == tag)
        return true;
    int count = 0;
    if (!importDelta(store, hourlyUrl(day, hour), cacheDir, &count, &e, nullptr)) {
        log << "Could not apply today's changes: " << e << "\n";
        return true;
    }
    store.setMeta("hour", tag);
    log << "Applied " << count << " changes from today up to " << QString("%1:00").arg(hour, 2, 10, QChar('0'))
        << " UTC.\n";
    return true;
}

} // namespace CveList
