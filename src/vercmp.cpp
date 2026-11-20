#include "vercmp.h"

#include <QByteArray>
#include <cstring>

namespace Vercmp {

namespace {

bool isDigit(char c) { return c >= '0' && c <= '9'; }
bool isAlpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool isAlnum(char c) { return isDigit(c) || isAlpha(c); }

// libalpm's rpmvercmp on byte strings; indices stand in for its pointers.
int rpmvercmpBytes(const QByteArray &a, const QByteArray &b) {
    if (a == b)
        return 0;
    const char *s1 = a.constData();
    const char *s2 = b.constData();
    const int n1 = a.size(), n2 = b.size();
    int one = 0, two = 0, ptr1 = 0, ptr2 = 0;

    while (one < n1 && two < n2) {
        while (one < n1 && !isAlnum(s1[one]))
            ++one;
        while (two < n2 && !isAlnum(s2[two]))
            ++two;
        if (!(one < n1 && two < n2))
            break;
        // Different lengths of separator end the comparison.
        if ((one - ptr1) != (two - ptr2))
            return (one - ptr1) < (two - ptr2) ? -1 : 1;

        ptr1 = one;
        ptr2 = two;
        bool isNum;
        if (isDigit(s1[ptr1])) {
            while (ptr1 < n1 && isDigit(s1[ptr1]))
                ++ptr1;
            while (ptr2 < n2 && isDigit(s2[ptr2]))
                ++ptr2;
            isNum = true;
        } else {
            while (ptr1 < n1 && isAlpha(s1[ptr1]))
                ++ptr1;
            while (ptr2 < n2 && isAlpha(s2[ptr2]))
                ++ptr2;
            isNum = false;
        }
        if (one == ptr1)
            return -1;
        // One numeric and one alpha segment: numeric is newer.
        if (two == ptr2)
            return isNum ? 1 : -1;

        QByteArray seg1(s1 + one, ptr1 - one);
        QByteArray seg2(s2 + two, ptr2 - two);
        if (isNum) {
            int z1 = 0, z2 = 0;
            while (z1 < seg1.size() && seg1[z1] == '0')
                ++z1;
            while (z2 < seg2.size() && seg2[z2] == '0')
                ++z2;
            seg1 = seg1.mid(z1);
            seg2 = seg2.mid(z2);
            if (seg1.size() != seg2.size())
                return seg1.size() > seg2.size() ? 1 : -1;
        }
        const int rc = std::strcmp(seg1.constData(), seg2.constData());
        if (rc)
            return rc < 1 ? -1 : 1;
        one = ptr1;
        two = ptr2;
    }

    if (one >= n1 && two >= n2)
        return 0;
    // A remaining alpha segment never beats an empty string.
    if ((one >= n1 && !isAlpha(s2[two])) || (one < n1 && isAlpha(s1[one])))
        return -1;
    return 1;
}

struct Evr {
    QByteArray epoch, version, release;
    bool hasRelease = false;
};

Evr parseEvr(const QByteArray &evr) {
    Evr out;
    int s = 0;
    while (s < evr.size() && isDigit(evr[s]))
        ++s;
    const int dash = evr.lastIndexOf('-');
    const int se = dash >= s ? dash : -1;
    int versionStart = 0;
    if (s < evr.size() && evr[s] == ':') {
        out.epoch = evr.left(s);
        if (out.epoch.isEmpty())
            out.epoch = "0";
        versionStart = s + 1;
    } else {
        out.epoch = "0";
    }
    if (se >= 0) {
        out.version = evr.mid(versionStart, se - versionStart);
        out.release = evr.mid(se + 1);
        out.hasRelease = true;
    } else {
        out.version = evr.mid(versionStart);
    }
    return out;
}

} // namespace

int rpmvercmp(const QString &a, const QString &b) { return rpmvercmpBytes(a.toLatin1(), b.toLatin1()); }

int compare(const QString &a, const QString &b) {
    if (a == b)
        return 0;
    const Evr x = parseEvr(a.toLatin1());
    const Evr y = parseEvr(b.toLatin1());
    int ret = rpmvercmpBytes(x.epoch, y.epoch);
    if (ret == 0) {
        ret = rpmvercmpBytes(x.version, y.version);
        if (ret == 0 && x.hasRelease && y.hasRelease)
            ret = rpmvercmpBytes(x.release, y.release);
    }
    return ret;
}

QString upstream(const QString &pacmanVersion) {
    QString v = pacmanVersion;
    const int colon = v.indexOf(':');
    if (colon >= 0) {
        bool numeric = colon > 0;
        for (int i = 0; i < colon; ++i)
            numeric = numeric && v.at(i).isDigit();
        if (numeric)
            v = v.mid(colon + 1);
    }
    const int dash = v.lastIndexOf('-');
    return dash > 0 ? v.left(dash) : v;
}

} // namespace Vercmp
