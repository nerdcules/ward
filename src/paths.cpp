#include "paths.h"

#include <QDir>

namespace Paths {

namespace {

QString xdg(const char *variable, const QString &fallback) {
    QString base = qEnvironmentVariable(variable);
    if (base.isEmpty() || !QDir::isAbsolutePath(base))
        base = QDir::homePath() + "/" + fallback;
    const QString dir = base + "/ward";
    QDir().mkpath(dir);
    return dir;
}

} // namespace

QString cache() { return xdg("XDG_CACHE_HOME", ".cache"); }
QString config() { return xdg("XDG_CONFIG_HOME", ".config"); }
QString state() { return xdg("XDG_STATE_HOME", ".local/state"); }

} // namespace Paths
