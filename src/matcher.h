#pragma once

#include "feeds.h"
#include "inventory.h"

#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

class Store;

// Puts the installed packages next to the advisories.
//
// Arch's tracker is exact: it names Arch packages and the package version
// that fixed them, so where it covers a CVE for a package, its answer wins,
// even over CVE.org (Arch often fixes by patching, so the upstream version
// in a CVE.org range can stay "affected" when the package is not).
//
// CVE.org records name products, not Arch packages. A package is looked up
// by its own name (lib32-x as x; python-x also as x, among PyPI products and
// products with no registry), the kernel packages as vendor "Linux"'s
// "Linux"/"linux_kernel", plus whatever names.json adds. Rows from language
// registries (npm, crates.io, Go modules...) are left for the project check.
// When names.json pins a package's vendors, rows from other vendors are
// dropped and a match is labelled "vendor"; otherwise it is "name", the
// weakest kind, and the one triage most needs to look at. A foreign package
// (AUR, or built here) with no names.json rule counts a record only when its
// vendor appears in the package's URL, which is then a "vendor" match.
namespace Matcher {

struct NameRule {
    QStringList products; // more product names to look up
    QStringList vendors;  // only these vendors count, when given
};
using Names = QHash<QString, NameRule>;

// The shipped names.json, overridden package by package by the user's.
Names loadNames(const QByteArray &shipped, const QByteArray &user);

struct Finding {
    QString cve, package, version, upstream;
    QString verdict; // "affected" or "unknown"
    QString source;  // "arch", "cna" or "adp"
    QString match;   // "tracker", "vendor" or "name"
    QString vendor, product, group, fixedIn, reason;
    QString title, description, published, severity;
    double score = -1;
    bool kev = false, foreign = false, kernel = false;
    QString kevAdded;
    QStringList files;  // the record's programFiles (kernel CVEs name them)
    QString where;      // kernel: where that code is here (Exposure::kernelWhere)
    // Triage: by Claude, or by Ward when the evidence settles it.
    QString applies, priority, why, triagedBy;
    QString updateTo;   // the version waiting in the repos, if any

    // What the finding is in. "system": a pacman package (`package`,
    // `version`). The other layers name what you act on in `package` and the
    // vulnerable part in `component` at `version`:
    //   "project"   a project's dependency: package = the project's folder
    //               name, location = its path, ecosystem = npm, NuGet...
    //   "docker"    a library in a Docker image: package = the image,
    //               location = its id
    //   "firmware"  a device's firmware: package = the device, location =
    //               fwupd's device id, component empty
    QString layer = QStringLiteral("system");
    QString component, location, ecosystem, advisory; // advisory: OSV's or trivy's id when not a CVE

    // What a finding is listed and triaged under: the package for the system
    // layer; for the others the layer and the location (two projects can
    // share a folder name, as a clone and a copy of it do).
    QString groupKey() const {
        return layer == "system" ? package : layer + ":" + (location.isEmpty() ? package : location);
    }
    QString id() const {
        if (layer == "system")
            return cve + "@" + package;
        return cve + "@" + groupKey() + (component.isEmpty() ? QString() : "/" + component + "@" + version);
    }
    QJsonObject toJson() const;
    static Finding fromJson(const QJsonObject &o);
};

QList<Finding> run(const QList<Inventory::Package> &packages, const QList<Feeds::ArchGroup> &arch,
                   const QHash<QString, Feeds::Kev> &kev, const Store &store, const Names &names);

// Most urgent first: exploited (KEV), then by how sure the match is
// (tracker, vendor, name), then by score.
void sort(QList<Finding> &findings);

} // namespace Matcher
