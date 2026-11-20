#pragma once

#include "feeds.h"
#include "matcher.h"

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

class Store;

// Local Docker images, scanned with trivy (an optional dependency). Each
// image is scanned once per image id and day; the result is kept in the
// cache. An image no running container uses is settled by Ward as "later":
// its flaws are in files nothing is running.
//
// Only an image's critical findings and those on CISA's exploited list are
// listed; the rest are counted per image, by severity. On 20 Nov 2026 the 29
// images here held 162,561 findings (156,541 in Debian packages of old
// toolchain images), which made a 321 MB findings.json; trivy's own report
// stays in the cache for the full list.
namespace Docker {

struct Image {
    QString id, ref;
    QStringList running, stopped; // container names
};

struct Run {
    bool available = false; // docker and trivy both there
    QList<Matcher::Finding> findings; // the listed ones
    QJsonObject exposure;   // group -> {summary, counts}
    int images = 0, scanned = 0, cached = 0, found = 0;
    QString error;
};

// Whether a finding is listed rather than only counted.
bool listed(const Matcher::Finding &f);

// Counts by severity, and how many have a fixed version or are exploited.
QJsonObject counts(const QList<Matcher::Finding> &all);

Run check(const QString &cacheDir, const Store &store, const QHash<QString, Feeds::Kev> &kev, bool offline);

// From trivy's JSON (`trivy image --format json`), for tests.
QList<Matcher::Finding> parseTrivy(const QByteArray &json, const Image &image, const Store &store,
                                   const QHash<QString, Feeds::Kev> &kev);
// From `docker image ls --format '{{json .}}'` and lines of
// "<image id> <state> /<name>" (docker inspect of every container).
QList<Image> parseImages(const QByteArray &images, const QByteArray &containers);
QString exposureSummary(const Image &image);

} // namespace Docker
