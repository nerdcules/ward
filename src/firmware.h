#pragma once

#include "feeds.h"
#include "matcher.h"

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QString>

class Store;

// Firmware, through fwupd: the CVEs a device's pending firmware release
// says it fixes (LVFS lists them as the release's "Issues"). Ward reads
// what fwupd already knows (`fwupdmgr get-updates --json`) and doesn't
// refresh LVFS's metadata itself; it reports how old that is.
namespace Firmware {

struct Run {
    bool available = false; // fwupdmgr is installed and answered
    QList<Matcher::Finding> findings;
    int devices = 0, updates = 0;
    QString metadataDate, error;
};

Run check(const Store &store, const QHash<QString, Feeds::Kev> &kev);

// From fwupdmgr's JSON (get-devices, get-updates, get-remotes), for tests.
Run parse(const QByteArray &devices, const QByteArray &updates, const QByteArray &remotes, const Store &store,
          const QHash<QString, Feeds::Kev> &kev);

} // namespace Firmware
