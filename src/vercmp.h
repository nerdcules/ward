#pragma once

#include <QString>

// pacman's version order, ported from libalpm (lib/libalpm/version.c) so
// that "is the installed package older than the fix" gives the answer
// pacman and vercmp(8) would. The tests compare it with /usr/bin/vercmp.
namespace Vercmp {

// One version string, no epoch or release: 10.6p1 < 10.6p2, 7.4rc1 < 7.4,
// 1.10 > 1.9. Returns -1, 0 or 1.
int rpmvercmp(const QString &a, const QString &b);

// A full pacman version, [epoch:]version[-release]. The releases count only
// when both sides have one, as in alpm_pkg_vercmp.
int compare(const QString &a, const QString &b);

// The upstream part of a pacman version: "2:9.0.2-2" gives "9.0.2". This is
// what advisories outside Arch talk about.
QString upstream(const QString &pacmanVersion);

} // namespace Vercmp
