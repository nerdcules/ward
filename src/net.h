#pragma once

#include <QByteArray>
#include <QString>
#include <QUrl>

// Blocking HTTP for the command line: each call runs its own event loop.
// Redirects are followed (GitHub release assets redirect to a CDN), and a
// transfer that sends nothing for 60 s is abandoned.
namespace Net {

// The body, or an empty array with `error` set. `status` gets the HTTP code.
QByteArray get(const QUrl &url, QString *error, int *status = nullptr);

// Streams the body to `path` through `path`.part, renamed only when complete.
bool download(const QUrl &url, const QString &path, QString *error, int *status = nullptr);

} // namespace Net
