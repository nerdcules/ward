#include "store.h"

#include "zip.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>
#include <QVariant>

namespace {

QString versionsJson(const QList<Cve5::Range> &versions) {
    QJsonArray list;
    for (const Cve5::Range &r : versions) {
        QJsonObject o{{"v", r.version}, {"s", r.status}};
        if (!r.lessThan.isEmpty())
            o.insert("lt", r.lessThan);
        if (!r.lessThanOrEqual.isEmpty())
            o.insert("lte", r.lessThanOrEqual);
        if (!r.type.isEmpty())
            o.insert("t", r.type);
        list.append(o);
    }
    return QString::fromUtf8(QJsonDocument(list).toJson(QJsonDocument::Compact));
}

QList<Cve5::Range> versionsFrom(const QString &json) {
    QList<Cve5::Range> out;
    for (const QJsonValue &v : QJsonDocument::fromJson(json.toUtf8()).array()) {
        const QJsonObject o = v.toObject();
        out.append({o.value("v").toString(), o.value("lt").toString(), o.value("lte").toString(),
                    o.value("s").toString(), o.value("t").toString()});
    }
    return out;
}

Cve5::Record recordFrom(const QSqlQuery &q, int first) {
    Cve5::Record r;
    r.id = q.value(first).toString();
    r.state = q.value(first + 1).toString();
    r.published = q.value(first + 2).toString();
    r.updated = q.value(first + 3).toString();
    r.title = q.value(first + 4).toString();
    r.description = q.value(first + 5).toString();
    r.score = q.value(first + 6).isNull() ? -1 : q.value(first + 6).toDouble();
    r.severity = q.value(first + 7).toString();
    return r;
}

Cve5::Affected affectedFrom(const QSqlQuery &q, int first) {
    Cve5::Affected a;
    a.vendor = q.value(first).toString();
    a.product = q.value(first + 1).toString();
    a.collection = q.value(first + 2).toString();
    a.package = q.value(first + 3).toString();
    a.defaultStatus = q.value(first + 4).toString();
    a.versions = versionsFrom(q.value(first + 5).toString());
    a.source = q.value(first + 6).toString();
    a.files = q.value(first + 7).toString().split('\n', Qt::SkipEmptyParts);
    return a;
}

const char *kRecordColumns = "c.id, c.state, c.published, c.updated, c.title, c.description, c.score, c.severity";
const char *kAffectedColumns =
    "a.vendor, a.product, a.collection, a.package, a.default_status, a.versions, a.source, a.files";
const int kSchema = 2;

} // namespace

Store::Store(const QString &path)
    : m_path(path), m_connection("ward-store-" + QUuid::createUuid().toString(QUuid::WithoutBraces)) {}

Store::~Store() {
    if (QSqlDatabase::contains(m_connection)) {
        QSqlDatabase::database(m_connection).close();
        QSqlDatabase::removeDatabase(m_connection);
    }
}

QSqlDatabase Store::db() const { return QSqlDatabase::database(m_connection, false); }

bool Store::open(QString *error) {
    QSqlDatabase d = QSqlDatabase::addDatabase("QSQLITE", m_connection);
    d.setDatabaseName(m_path);
    if (!d.open()) {
        if (error)
            *error = d.lastError().text();
        return false;
    }
    QSqlQuery q(d);
    // Schema 2 added affected.files. An older file is started again: its rows
    // lack the column's data, which only a fresh baseline can fill.
    if (q.exec("SELECT value FROM meta WHERE key = 'schema'") && (!q.next() || q.value(0).toInt() < kSchema)) {
        if (q.exec("SELECT COUNT(*) FROM cve") && q.next() && q.value(0).toInt() > 0)
            m_reset = true;
        for (const char *table : {"cve", "affected", "meta"})
            q.exec(QString("DROP TABLE IF EXISTS %1").arg(table));
    }
    const QStringList schema{
        "PRAGMA journal_mode=WAL",
        "CREATE TABLE IF NOT EXISTS cve (id TEXT PRIMARY KEY, state TEXT, published TEXT, updated TEXT, "
        "title TEXT, description TEXT, score REAL, severity TEXT)",
        "CREATE TABLE IF NOT EXISTS affected (cve TEXT, key TEXT, vendor TEXT, product TEXT, collection TEXT, "
        "package TEXT, default_status TEXT, versions TEXT, source TEXT, files TEXT)",
        "CREATE INDEX IF NOT EXISTS affected_key ON affected(key)",
        "CREATE INDEX IF NOT EXISTS affected_cve ON affected(cve)",
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
    };
    for (const QString &statement : schema) {
        if (!q.exec(statement)) {
            if (error)
                *error = q.lastError().text();
            return false;
        }
    }
    q.exec(QString("INSERT OR IGNORE INTO meta VALUES ('schema', '%1')").arg(kSchema));
    return true;
}

bool Store::put(const Cve5::Record &r) {
    if (r.id.isEmpty()) {
        m_lastError = "a record without an id";
        return false;
    }
    QSqlDatabase d = db();
    QSqlQuery q(d);
    q.prepare("SELECT updated FROM cve WHERE id = ?");
    q.addBindValue(r.id);
    if (q.exec() && q.next() && !r.updated.isEmpty() && q.value(0).toString() > r.updated)
        return true; // the stored copy is newer

    q.prepare("INSERT OR REPLACE INTO cve VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    q.addBindValue(r.id);
    q.addBindValue(r.state);
    q.addBindValue(r.published);
    q.addBindValue(r.updated);
    q.addBindValue(r.title);
    q.addBindValue(r.description.left(2000));
    q.addBindValue(r.score >= 0 ? QVariant(r.score) : QVariant());
    q.addBindValue(r.severity);
    if (!q.exec()) {
        m_lastError = r.id + ": " + q.lastError().text();
        return false;
    }
    q.prepare("DELETE FROM affected WHERE cve = ?");
    q.addBindValue(r.id);
    q.exec();
    if (r.state != "PUBLISHED")
        return true;
    for (const Cve5::Affected &a : r.affected) {
        q.prepare("INSERT INTO affected VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        q.addBindValue(r.id);
        q.addBindValue(a.key());
        q.addBindValue(a.vendor);
        q.addBindValue(a.product);
        q.addBindValue(a.collection);
        q.addBindValue(a.package);
        q.addBindValue(a.defaultStatus);
        q.addBindValue(versionsJson(a.versions));
        q.addBindValue(a.source);
        q.addBindValue(a.files.join('\n'));
        if (!q.exec()) {
            m_lastError = r.id + ": " + q.lastError().text();
            return false;
        }
    }
    return true;
}

bool Store::importZip(const QString &zip, int *count, QString *error) {
    QSqlDatabase d = db();
    d.transaction();
    int n = 0;
    bool failed = false;
    const bool read = Zip::forEachJson(
        zip,
        [&](const QString &, const QByteArray &data) {
            // cves/delta.json and cves/deltaLog.json are logs, not records.
            const QJsonDocument doc = QJsonDocument::fromJson(data);
            const Cve5::Record record = Cve5::parse(doc.object());
            if (record.id.isEmpty())
                return true;
            if (!put(record)) {
                failed = true;
                return false;
            }
            ++n;
            return true;
        },
        error);
    if (!read || failed) {
        d.rollback();
        if (failed && error)
            *error = QString("could not store record %1: %2").arg(n + 1).arg(m_lastError);
        return false;
    }
    if (!d.commit()) {
        if (error)
            *error = d.lastError().text();
        return false;
    }
    if (count)
        *count = n;
    return true;
}

QString Store::meta(const QString &key) const {
    QSqlQuery q(db());
    q.prepare("SELECT value FROM meta WHERE key = ?");
    q.addBindValue(key);
    return q.exec() && q.next() ? q.value(0).toString() : QString();
}

void Store::setMeta(const QString &key, const QString &value) {
    QSqlQuery q(db());
    q.prepare("INSERT OR REPLACE INTO meta VALUES (?, ?)");
    q.addBindValue(key);
    q.addBindValue(value);
    q.exec();
}

int Store::records() const {
    QSqlQuery q(db());
    return q.exec("SELECT COUNT(*) FROM cve") && q.next() ? q.value(0).toInt() : 0;
}

QList<Store::Row> Store::rows(const QStringList &keys) const {
    QList<Row> out;
    if (keys.isEmpty())
        return out;
    QStringList marks;
    for (int i = 0; i < keys.size(); ++i)
        marks << "?";
    QSqlQuery q(db());
    q.prepare(QString("SELECT %1, %2 FROM affected a JOIN cve c ON c.id = a.cve "
                      "WHERE a.key IN (%3) AND c.state = 'PUBLISHED'")
                  .arg(kRecordColumns, kAffectedColumns, marks.join(',')));
    for (const QString &k : keys)
        q.addBindValue(k);
    if (!q.exec())
        return out;
    while (q.next())
        out.append({recordFrom(q, 0), affectedFrom(q, 8)});
    return out;
}

bool Store::record(const QString &id, Cve5::Record *out) const {
    QSqlQuery q(db());
    q.prepare(QString("SELECT %1 FROM cve c WHERE c.id = ?").arg(kRecordColumns));
    q.addBindValue(id);
    if (!q.exec() || !q.next())
        return false;
    *out = recordFrom(q, 0);
    q.prepare(QString("SELECT %1 FROM affected a WHERE a.cve = ?").arg(kAffectedColumns));
    q.addBindValue(id);
    if (q.exec())
        while (q.next())
            out->affected.append(affectedFrom(q, 0));
    return true;
}
