#pragma once

#include "cve5.h"

#include <QSqlDatabase>
#include <QString>
#include <QStringList>

// Ward's copy of the CVE list: an SQLite file with each record's summary and
// every product it names, looked up by normalised product name. Rejected
// records keep their row (so a later delta can't bring back a stale copy) but
// lose their products.
class Store {
public:
    explicit Store(const QString &path);
    ~Store();

    bool open(QString *error);
    // True when open() found a file from an older Ward and emptied it; the
    // next sync downloads the baseline again.
    bool wasReset() const { return m_reset; }
    QString path() const { return m_path; }

    // Adds or replaces a record, unless the stored copy was updated later.
    bool put(const Cve5::Record &record);
    // A whole zip of records (a delta or the inner baseline), in one
    // transaction. Counts the records read.
    bool importZip(const QString &zip, int *count, QString *error);

    QString meta(const QString &key) const;
    void setMeta(const QString &key, const QString &value);

    int records() const;

    struct Row {
        Cve5::Record record; // id, state, dates, title, description, score
        Cve5::Affected affected;
    };
    // Every product row whose key is one of `keys`, for published records.
    QList<Row> rows(const QStringList &keys) const;
    // One record with all its products.
    bool record(const QString &id, Cve5::Record *out) const;

private:
    QString m_path, m_connection, m_lastError;
    bool m_reset = false;
    QSqlDatabase db() const;
};
