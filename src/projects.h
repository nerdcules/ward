#pragma once

#include <QList>
#include <QString>
#include <QStringList>

// The dependencies of the projects under a few folders (~/Work and
// ~/Projects unless ward.json says otherwise), read from what the build
// tools resolved, never from what a manifest asks for:
//   npm     package-lock.json (lockfileVersion 2 and 3, and 1)
//   NuGet   obj/project.assets.json, which `dotnet restore` writes with
//           every package, transitive ones included
//   crates  Cargo.lock
//   PyPI    requirements*.txt, pinned lines (name==version) only
// A project without one of these (a .csproj never restored, a Gradle build
// without a lock) isn't seen.
namespace Projects {

struct Dependency {
    QString ecosystem, name, version; // OSV's ecosystem names: npm, NuGet, crates.io, PyPI
    QString project;                   // the project's folder
    QString file;                      // the file it was read from
    bool dev = false;                  // npm's "dev": only used to develop the project
};

struct Scan {
    QList<Dependency> dependencies;
    QStringList files;   // every file read
    QStringList errors;  // files that couldn't be read
};

// Folders under `roots`, skipping node_modules, .git, build output and
// virtualenvs, at most `depth` levels down.
Scan scan(const QStringList &roots, int depth = 6);

// The parsers, for tests.
QList<Dependency> parseNpmLock(const QByteArray &json, const QString &project, const QString &file);
QList<Dependency> parseAssets(const QByteArray &json, const QString &project, const QString &file);
QList<Dependency> parseCargoLock(const QString &text, const QString &project, const QString &file);
QList<Dependency> parseRequirements(const QString &text, const QString &project, const QString &file);

// The folders to scan: ward.json's "projectRoots", else ~/Work and ~/Projects
// where they exist.
QStringList roots(const QString &configFile);

} // namespace Projects
