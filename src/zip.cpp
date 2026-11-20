#include "zip.h"

#include <QFile>

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <unistd.h>

namespace Zip {

namespace {

struct Reader {
    archive *a = archive_read_new();
    ~Reader() { archive_read_free(a); }
};

bool open(Reader &r, const QString &zip, QString *error) {
    archive_read_support_format_zip(r.a);
    if (archive_read_open_filename(r.a, QFile::encodeName(zip).constData(), 1 << 20) != ARCHIVE_OK) {
        if (error)
            *error = QString("%1: %2").arg(zip, QString::fromLocal8Bit(archive_error_string(r.a)));
        return false;
    }
    return true;
}

} // namespace

bool extract(const QString &zip, const QString &name, const QString &destination, QString *error) {
    Reader r;
    if (!open(r, zip, error))
        return false;
    archive_entry *entry;
    while (archive_read_next_header(r.a, &entry) == ARCHIVE_OK) {
        if (QString::fromUtf8(archive_entry_pathname(entry)) != name)
            continue;
        const int fd = ::open(QFile::encodeName(destination).constData(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            if (error)
                *error = "Could not write " + destination;
            return false;
        }
        const int rc = archive_read_data_into_fd(r.a, fd);
        ::close(fd);
        if (rc != ARCHIVE_OK) {
            if (error)
                *error = QString("%1: %2").arg(zip, QString::fromLocal8Bit(archive_error_string(r.a)));
            return false;
        }
        return true;
    }
    if (error)
        *error = QString("%1 has no %2").arg(zip, name);
    return false;
}

bool forEachJson(const QString &zip, const std::function<bool(const QString &, const QByteArray &)> &each,
                 QString *error) {
    Reader r;
    if (!open(r, zip, error))
        return false;
    archive_entry *entry;
    int rc;
    while ((rc = archive_read_next_header(r.a, &entry)) == ARCHIVE_OK) {
        const QString path = QString::fromUtf8(archive_entry_pathname(entry));
        if (!path.endsWith(".json"))
            continue;
        QByteArray data;
        const la_int64_t size = archive_entry_size(entry);
        if (size > 0)
            data.reserve(size);
        char buffer[65536];
        la_ssize_t n;
        while ((n = archive_read_data(r.a, buffer, sizeof buffer)) > 0)
            data.append(buffer, n);
        if (n < 0) {
            if (error)
                *error = QString("%1: %2").arg(path, QString::fromLocal8Bit(archive_error_string(r.a)));
            return false;
        }
        if (!each(path, data))
            return true;
    }
    if (rc != ARCHIVE_EOF) {
        if (error)
            *error = QString("%1: %2").arg(zip, QString::fromLocal8Bit(archive_error_string(r.a)));
        return false;
    }
    return true;
}

} // namespace Zip
