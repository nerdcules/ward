#include "projects.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>

namespace Projects {

namespace {

const QSet<QString> kSkip{"node_modules", ".git", "build", "target", "vendor", ".venv", "venv", "bin",
                          "dist", "out", "__pycache__", ".cache", "worktrees", ".gradle"};

void walk(const QString &dir, int depth, QStringList &found) {
    if (depth < 0)
        return;
    const QFileInfoList entries =
        QDir(dir).entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::NoSymLinks);
    for (const QFileInfo &e : entries) {
        const QString name = e.fileName();
        if (e.isDir()) {
            // A restored .NET project keeps its package list in obj/.
            if (name == "obj") {
                const QString assets = e.filePath() + "/project.assets.json";
                if (QFile::exists(assets))
                    found << assets;
                continue;
            }
            if (!kSkip.contains(name))
                walk(e.filePath(), depth - 1, found);
            continue;
        }
        if (name == "package-lock.json" || name == "Cargo.lock" ||
            (name.startsWith("requirements") && name.endsWith(".txt")))
            found << e.filePath();
    }
}

QByteArray read(const QString &path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

// npm lockfile v1: nested "dependencies".
void npmV1(const QJsonObject &deps, const QString &project, const QString &file, QList<Dependency> &out) {
    for (auto it = deps.begin(); it != deps.end(); ++it) {
        const QJsonObject d = it.value().toObject();
        const QString version = d.value("version").toString();
        if (!version.isEmpty() && !version.startsWith("file:") && !version.contains("://"))
            out.append({"npm", it.key(), version, project, file, d.value("dev").toBool()});
        npmV1(d.value("dependencies").toObject(), project, file, out);
    }
}

} // namespace

QList<Dependency> parseNpmLock(const QByteArray &json, const QString &project, const QString &file) {
    QList<Dependency> out;
    const QJsonObject root = QJsonDocument::fromJson(json).object();
    const QJsonObject packages = root.value("packages").toObject();
    if (packages.isEmpty()) {
        npmV1(root.value("dependencies").toObject(), project, file, out);
        return out;
    }
    for (auto it = packages.begin(); it != packages.end(); ++it) {
        if (it.key().isEmpty())
            continue; // the project itself
        const QJsonObject p = it.value().toObject();
        const QString version = p.value("version").toString();
        if (version.isEmpty() || p.value("link").toBool())
            continue; // a workspace link, not a package from the registry
        // "node_modules/a/node_modules/@scope/b" is @scope/b.
        const QString name = p.value("name").toString(it.key().section("node_modules/", -1));
        out.append({"npm", name, version, project, file, p.value("dev").toBool()});
    }
    return out;
}

QList<Dependency> parseAssets(const QByteArray &json, const QString &project, const QString &file) {
    QList<Dependency> out;
    const QJsonObject libraries = QJsonDocument::fromJson(json).object().value("libraries").toObject();
    for (auto it = libraries.begin(); it != libraries.end(); ++it) {
        if (it.value().toObject().value("type").toString() != "package")
            continue; // project references are this repo's own code
        const QString name = it.key().section('/', 0, 0), version = it.key().section('/', 1);
        if (!name.isEmpty() && !version.isEmpty())
            out.append({"NuGet", name, version, project, file, false});
    }
    return out;
}

QList<Dependency> parseCargoLock(const QString &text, const QString &project, const QString &file) {
    QList<Dependency> out;
    QString name, version, source;
    auto flush = [&] {
        // Only crates from crates.io; path and git dependencies are not in OSV.
        if (!name.isEmpty() && !version.isEmpty() && source.startsWith("registry+"))
            out.append({"crates.io", name, version, project, file, false});
        name.clear();
        version.clear();
        source.clear();
    };
    static const QRegularExpression field(R"re(^(\w+)\s*=\s*"([^"]*)")re");
    for (const QString &line : text.split('\n')) {
        if (line.trimmed() == "[[package]]") {
            flush();
            continue;
        }
        const auto m = field.match(line.trimmed());
        if (!m.hasMatch())
            continue;
        if (m.captured(1) == "name")
            name = m.captured(2);
        else if (m.captured(1) == "version")
            version = m.captured(2);
        else if (m.captured(1) == "source")
            source = m.captured(2);
    }
    flush();
    return out;
}

QList<Dependency> parseRequirements(const QString &text, const QString &project, const QString &file) {
    QList<Dependency> out;
    static const QRegularExpression pinned(R"(^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+))");
    for (const QString &line : text.split('\n')) {
        const auto m = pinned.match(line.trimmed());
        if (m.hasMatch())
            out.append({"PyPI", m.captured(1), m.captured(3), project, file, false});
    }
    return out;
}

Scan scan(const QStringList &roots, int depth) {
    Scan s;
    QStringList files;
    for (const QString &root : roots)
        walk(root, depth, files);
    for (const QString &file : files) {
        const QFileInfo info(file);
        // obj/project.assets.json belongs to the folder above obj.
        const QString project = info.fileName() == "project.assets.json" ? info.dir().absolutePath().section('/', 0, -2)
                                                                          : info.dir().absolutePath();
        const QByteArray data = read(file);
        if (data.isEmpty()) {
            s.errors << file;
            continue;
        }
        QList<Dependency> deps;
        if (info.fileName() == "package-lock.json")
            deps = parseNpmLock(data, project, file);
        else if (info.fileName() == "project.assets.json")
            deps = parseAssets(data, project, file);
        else if (info.fileName() == "Cargo.lock")
            deps = parseCargoLock(QString::fromUtf8(data), project, file);
        else
            deps = parseRequirements(QString::fromUtf8(data), project, file);
        s.files << file;
        s.dependencies += deps;
    }
    return s;
}

QStringList roots(const QString &configFile) {
    QStringList out;
    QFile f(configFile);
    if (f.open(QIODevice::ReadOnly)) {
        for (const QJsonValue &v : QJsonDocument::fromJson(f.readAll()).object().value("projectRoots").toArray()) {
            QString path = v.toString();
            if (path.startsWith("~/"))
                path = QDir::homePath() + path.mid(1);
            out << path;
        }
        if (!out.isEmpty())
            return out;
    }
    for (const char *name : {"Work", "Projects"})
        if (QFileInfo(QDir::homePath() + "/" + name).isDir())
            out << QDir::homePath() + "/" + name;
    return out;
}

} // namespace Projects
