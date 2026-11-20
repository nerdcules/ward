#pragma once

#include <QByteArray>
#include <QString>
#include <functional>

// Reading the CVE.org zips with libarchive, without unpacking them to disk:
// the baseline is a zip holding one zip (cves.zip) of about 430,000 JSON files.
namespace Zip {

// Copies the member `name` of `zip` to the file `destination`.
bool extract(const QString &zip, const QString &name, const QString &destination, QString *error);

// Calls `each` with the path and contents of every member ending in .json.
// `each` returns false to stop early.
bool forEachJson(const QString &zip, const std::function<bool(const QString &, const QByteArray &)> &each,
                 QString *error);

} // namespace Zip
