#pragma once

#include <QString>

// Where Ward keeps things, following the XDG base directories:
// cache  ~/.cache/ward        feeds and the CVE list (cve.sqlite); can be deleted
// config ~/.config/ward       names.json
// state  ~/.local/state/ward  findings.json, the last check's results
namespace Paths {

QString cache();
QString config();
QString state();

} // namespace Paths
