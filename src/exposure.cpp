#include "exposure.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QProcess>
#include <QRegularExpression>
#include <QSysInfo>

namespace Exposure {

namespace {

QString readText(const QString &path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? QString::fromUtf8(f.readAll()) : QString();
}

QString run(const QString &program, const QStringList &arguments) {
    QProcess p;
    p.start(program, arguments);
    if (!p.waitForFinished(60000))
        return {};
    return QString::fromUtf8(p.readAllStandardOutput());
}

// "kernel/drivers/net/virtio_net.ko.zst" -> "kernel/drivers/net/virtio_net"
QString stripKo(const QString &path) {
    const int ko = path.indexOf(".ko");
    return ko > 0 ? path.left(ko) : path;
}

// Architectures this machine isn't; a CVE only in their code can't apply.
bool otherArch(const QString &file) {
    static const QString mine = QSysInfo::currentCpuArchitecture() == "x86_64" ? "x86" : QSysInfo::currentCpuArchitecture();
    if (file.startsWith("arch/"))
        return file.section('/', 1, 1) != mine;
    static const QStringList foreignDrivers{"drivers/s390/", "drivers/parisc/", "drivers/sbus/", "drivers/macintosh/",
                                            "drivers/tc/", "drivers/zorro/", "drivers/nubus/", "drivers/sh/"};
    for (const QString &d : foreignDrivers)
        if (file.startsWith(d))
            return true;
    return false;
}

int rank(const QString &where) {
    static const QStringList order{"loaded", "built-in", "core", "unclear", "not-loaded", "other-arch", "unknown"};
    const int i = order.indexOf(where);
    return i < 0 ? order.size() : i;
}

QStringList sorted(QSet<QString> set) {
    QStringList list(set.begin(), set.end());
    list.sort();
    return list;
}

} // namespace

Kernel readKernel(const QString &package, const QString &modulesRoot, const QString &procModules,
                  const QString &runningRelease) {
    Kernel k;
    for (const QString &release : QDir(modulesRoot).entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        if (readText(modulesRoot + "/" + release + "/pkgbase").trimmed() == package) {
            k.release = release;
            break;
        }
    }
    if (k.release.isEmpty())
        return k;
    const QString running = runningRelease.isEmpty() ? QSysInfo::kernelVersion() : runningRelease;
    k.running = running == k.release;
    const QString dir = modulesRoot + "/" + k.release;
    for (const QString &line : readText(dir + "/modules.dep").split('\n', Qt::SkipEmptyParts)) {
        const QString path = stripKo(line.section(':', 0, 0));
        k.modules.insert(path, path.section('/', -1).replace('-', '_'));
    }
    for (const QString &line : readText(dir + "/modules.builtin").split('\n', Qt::SkipEmptyParts))
        k.builtin.insert(stripKo(line.trimmed()));
    if (k.running)
        for (const QString &line : readText(procModules).split('\n', Qt::SkipEmptyParts))
            k.loaded.insert(line.section(' ', 0, 0));
    return k;
}

QString kernelWhere(const Kernel &k, const QString &file) {
    if (otherArch(file))
        return "other-arch";
    QString folder = file.section('/', 0, -2);
    const QString base = file.section('/', -1).section('.', 0, 0);
    const QString exact = "kernel/" + folder + "/" + base;
    if (k.builtin.contains(exact))
        return "built-in";
    if (k.modules.contains(exact))
        return k.loaded.contains(k.modules.value(exact)) ? "loaded" : "not-loaded";
    // The deepest folder above the file that holds modules.
    while (!folder.isEmpty()) {
        const QString prefix = "kernel/" + folder + "/";
        QStringList here;
        bool anyBuiltin = false;
        for (auto it = k.modules.constBegin(); it != k.modules.constEnd(); ++it)
            if (it.key().startsWith(prefix) && !it.key().mid(prefix.size()).contains('/'))
                here << it.key();
        for (const QString &b : k.builtin)
            if (b.startsWith(prefix) && !b.mid(prefix.size()).contains('/'))
                anyBuiltin = true;
        if (!here.isEmpty() || anyBuiltin) {
            if (anyBuiltin)
                return "built-in";
            bool anyLoaded = false;
            for (const QString &m : here)
                anyLoaded = anyLoaded || k.loaded.contains(k.modules.value(m));
            if (anyLoaded)
                return "loaded";
            // One module in the folder is the file's module; with several, a
            // file named after none of them may be built in (obj-y).
            return here.size() == 1 ? "not-loaded" : "unclear";
        }
        folder = folder.contains('/') ? folder.section('/', 0, -2) : QString();
    }
    return "core";
}

QString kernelWhere(const Kernel &k, const QStringList &files) {
    QString best = "unknown";
    for (const QString &f : files) {
        const QString w = kernelWhere(k, f);
        if (rank(w) < rank(best))
            best = w;
    }
    return best;
}

QJsonObject Package::toJson() const {
    return {{"units", QJsonArray::fromStringList(units)},
            {"processes", QJsonArray::fromStringList(processes)},
            {"usedBy", QJsonArray::fromStringList(users)},
            {"listening", QJsonArray::fromStringList(listening)},
            {"explicit", explicitInstall}};
}

QString Package::summary() const {
    QStringList parts;
    if (!units.isEmpty())
        parts << "active units: " + units.join(", ");
    if (!processes.isEmpty())
        parts << "running: " + processes.join(", ");
    if (!listening.isEmpty())
        parts << "listening: " + listening.join(", ");
    if (!users.isEmpty())
        parts << "loaded by: " + users.mid(0, 8).join(", ") + (users.size() > 8 ? QString(" and %1 more").arg(users.size() - 8) : "");
    if (parts.isEmpty())
        parts << "nothing running uses it that Ward can see";
    parts << (explicitInstall ? "installed explicitly" : "installed as a dependency");
    return parts.join("; ");
}

QHash<QString, Package> forPackages(const QStringList &names) {
    QHash<QString, Package> out;
    if (names.isEmpty())
        return out;
    for (const QString &n : names)
        out.insert(n, {});

    // Every file of every package named, in one pacman call.
    QHash<QString, QString> owner;       // path -> package
    QHash<QString, QString> binaryOwner; // basename of an executable -> package
    QHash<QString, QStringList> unitFiles;
    for (const QString &line : run("pacman", QStringList{"-Ql"} + names).split('\n', Qt::SkipEmptyParts)) {
        const QString pkg = line.section(' ', 0, 0), path = line.section(' ', 1);
        if (path.endsWith('/'))
            continue;
        owner.insert(path, pkg);
        if (path.startsWith("/usr/bin/") ||
            (path.startsWith("/usr/lib/") && QFileInfo(path).isExecutable() && !path.contains(".so")))
            binaryOwner.insert(path.section('/', -1), pkg);
        static const QRegularExpression unit(R"(^/usr/lib/systemd/(system|user)/[^/]+\.(service|socket|timer)$)");
        if (unit.match(path).hasMatch())
            unitFiles[pkg] << path.section('/', -1);
    }

    const QSet<QString> explicitSet = [] {
        QSet<QString> s;
        for (const QString &n : run("pacman", {"-Qqe"}).split('\n', Qt::SkipEmptyParts))
            s.insert(n);
        return s;
    }();

    // Active units, system and user.
    QSet<QString> active;
    for (const QStringList &args : {QStringList{"list-units", "--state=active", "--no-legend", "--plain"},
                                    QStringList{"--user", "list-units", "--state=active", "--no-legend", "--plain"}})
        for (const QString &line : run("systemctl", args).split('\n', Qt::SkipEmptyParts))
            active.insert(line.section(' ', 0, 0, QString::SectionSkipEmpty));

    // Processes: every /proc/<pid>. The name (comm, cut to 15 characters) is
    // readable for all; exe and maps only for this user's own.
    QHash<QString, QSet<QString>> processes, users;
    QHash<QString, QString> pidName;
    for (const QString &pid : QDir("/proc").entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        if (!pid.at(0).isDigit())
            continue;
        const QString comm = readText("/proc/" + pid + "/comm").trimmed();
        pidName.insert(pid, comm);
        const QString exe = QFileInfo("/proc/" + pid + "/exe").symLinkTarget();
        if (!exe.isEmpty() && owner.contains(exe)) {
            processes[owner.value(exe)].insert(comm);
        } else if (exe.isEmpty()) {
            for (auto it = binaryOwner.constBegin(); it != binaryOwner.constEnd(); ++it)
                if (it.key().left(15) == comm)
                    processes[it.value()].insert(comm);
        }
        const QString maps = readText("/proc/" + pid + "/maps");
        if (maps.isEmpty())
            continue;
        QSet<QString> seen;
        for (const QString &line : maps.split('\n', Qt::SkipEmptyParts)) {
            const int slash = line.indexOf('/');
            if (slash < 0)
                continue;
            const QString path = line.mid(slash);
            if (seen.contains(path))
                continue;
            seen.insert(path);
            const QString pkg = owner.value(path);
            if (!pkg.isEmpty() && path != exe)
                users[pkg].insert(comm);
        }
    }

    // Listening sockets, with the process when ss may show it (own processes).
    QHash<QString, QStringList> listeningByName;
    static const QRegularExpression proc(R"re(\("([^"]+)",pid=(\d+))re");
    for (const QString &line : run("ss", {"-tulpnH"}).split('\n', Qt::SkipEmptyParts)) {
        const QStringList f = line.split(' ', Qt::SkipEmptyParts);
        if (f.size() < 5)
            continue;
        const auto m = proc.match(line);
        if (m.hasMatch())
            listeningByName[m.captured(1)] << QString("%1 %2 (%3)").arg(f.at(0), f.at(4), m.captured(1));
    }

    for (auto it = out.begin(); it != out.end(); ++it) {
        Package &p = it.value();
        const QString pkg = it.key();
        for (const QString &u : unitFiles.value(pkg))
            if (active.contains(u))
                p.units << u;
        p.processes = sorted(processes.value(pkg));
        p.users = sorted(users.value(pkg));
        for (const QString &name : p.processes)
            p.listening += listeningByName.value(name);
        p.explicitInstall = explicitSet.contains(pkg);
    }
    return out;
}

} // namespace Exposure
