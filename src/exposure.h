#pragma once

#include <QHash>
#include <QJsonObject>
#include <QSet>
#include <QString>
#include <QStringList>

// How much of a package this machine actually uses: evidence gathered
// without Claude, which triage then reads. Running as the user, Ward sees
// every process's name but only its own processes' files and sockets, so
// root daemons are known by their units and names, not by what they map.
namespace Exposure {

// --- the kernel -------------------------------------------------------------

struct Kernel {
    QString release;                // 7.2.15-1-omarchy
    bool running = false;           // is it the booted kernel?
    QHash<QString, QString> modules; // "kernel/drivers/net/virtio_net" -> "virtio_net"
    QSet<QString> builtin;          // "kernel/mm/zsmalloc", from modules.builtin
    QSet<QString> loaded;           // names from /proc/modules
};

// The kernel installed by `package`, found by the pkgbase file in its
// /usr/lib/modules/<release> folder.
Kernel readKernel(const QString &package, const QString &modulesRoot = "/usr/lib/modules",
                  const QString &procModules = "/proc/modules", const QString &runningRelease = {});

// Where one source file of a CVE lives in that kernel:
//   "loaded"      its module is loaded now
//   "built-in"    compiled into the kernel
//   "not-loaded"  a module that isn't loaded (some load on demand, so not safe)
//   "other-arch"  arch/<not x86>/ or a driver only built there (s390...)
//   "core"        no module anywhere above it: core kernel code, always in
//   "unclear"     a folder of several modules, none named after the file
QString kernelWhere(const Kernel &kernel, const QString &file);

// The most exposed answer across a CVE's files; "unknown" with none.
QString kernelWhere(const Kernel &kernel, const QStringList &files);

// --- other packages ---------------------------------------------------------

struct Package {
    QStringList units;     // its systemd units that are active (system or user)
    QStringList processes; // running processes started from its binaries
    QStringList users;     // own processes mapping one of its libraries
    QStringList listening; // sockets those processes listen on: "tcp 0.0.0.0:22 (sshd)"
    bool explicitInstall = false;
    QJsonObject toJson() const;
    QString summary() const; // one line for the table and for Claude
};

// One pass over pacman's file lists, systemd, /proc and ss for every
// package named.
QHash<QString, Package> forPackages(const QStringList &names);

} // namespace Exposure
