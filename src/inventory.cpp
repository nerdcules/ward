#include "inventory.h"

#include <QDir>
#include <QHash>
#include <QFile>
#include <QProcess>
#include <QSet>

namespace Inventory {

namespace {

QString run(const QString &program, const QStringList &arguments, QString *error) {
    QProcess p;
    p.start(program, arguments);
    if (!p.waitForFinished(60000) || p.exitStatus() != QProcess::NormalExit) {
        if (error)
            *error = QString("%1 %2 did not finish").arg(program, arguments.join(' '));
        return {};
    }
    return QString::fromUtf8(p.readAllStandardOutput());
}

QSet<QString> lines(const QString &text) {
    QSet<QString> out;
    for (const QString &line : text.split('\n', Qt::SkipEmptyParts))
        out.insert(line.trimmed());
    return out;
}

} // namespace

QList<Package> parse(const QString &all, const QString &foreign, const QString &kernels,
                     const QString &foreignInfo) {
    const QSet<QString> foreignSet = lines(foreign), kernelSet = lines(kernels);
    // "Name            : drift" ... "URL             : None"
    QHash<QString, QString> urls;
    QString name;
    for (const QString &line : foreignInfo.split('\n')) {
        const QString key = line.section(':', 0, 0).trimmed(), value = line.section(':', 1).trimmed();
        if (key == "Name")
            name = value;
        else if (key == "URL" && !name.isEmpty() && value != "None")
            urls.insert(name, value);
    }
    QList<Package> out;
    for (const QString &line : all.split('\n', Qt::SkipEmptyParts)) {
        const QStringList parts = line.split(' ', Qt::SkipEmptyParts);
        if (parts.size() != 2)
            continue;
        out.append({parts.at(0), parts.at(1), foreignSet.contains(parts.at(0)), kernelSet.contains(parts.at(0)),
                    urls.value(parts.at(0))});
    }
    return out;
}

QList<Package> packages(QString *error) {
    const QString all = run("pacman", {"-Q"}, error);
    if (all.isEmpty())
        return {};
    // -Qqm exits 1 when nothing is foreign; that is not an error.
    const QString foreign = run("pacman", {"-Qqm"}, nullptr);
    QStringList images;
    for (const QString &dir : QDir("/usr/lib/modules").entryList(QDir::Dirs | QDir::NoDotAndDotDot))
        if (QFile::exists("/usr/lib/modules/" + dir + "/vmlinuz"))
            images << "/usr/lib/modules/" + dir + "/vmlinuz";
    const QString kernels = images.isEmpty() ? QString() : run("pacman", QStringList{"-Qoq"} + images, nullptr);
    const QStringList foreignNames = foreign.split('\n', Qt::SkipEmptyParts);
    const QString info = foreignNames.isEmpty() ? QString() : run("pacman", QStringList{"-Qi"} + foreignNames, nullptr);
    return parse(all, foreign, kernels, info);
}

} // namespace Inventory
