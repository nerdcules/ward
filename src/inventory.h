#pragma once

#include <QList>
#include <QString>

// What is installed, as pacman sees it.
namespace Inventory {

struct Package {
    QString name, version; // version as pacman has it: [epoch:]version-release
    bool foreign = false;  // not from a sync repository (AUR, or built here)
    bool kernel = false;   // ships a kernel image under /usr/lib/modules
    QString url;           // upstream URL from `pacman -Qi`, read for foreign packages only
};

// `pacman -Q`, `pacman -Qqm`, and the owners of /usr/lib/modules/*/vmlinuz.
QList<Package> packages(QString *error);

// The same from text, for tests: `pacman -Q` output, `-Qqm` output, and the
// kernel package names, and `pacman -Qi` output for the foreign ones.
QList<Package> parse(const QString &all, const QString &foreign, const QString &kernels,
                     const QString &foreignInfo = {});

} // namespace Inventory
