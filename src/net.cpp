#include "net.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace Net {

namespace {

QNetworkRequest request(const QUrl &url) {
    QNetworkRequest r(url);
    r.setHeader(QNetworkRequest::UserAgentHeader,
                QString("ward/%1").arg(QCoreApplication::applicationVersion()));
    r.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    r.setTransferTimeout(60000);
    return r;
}

bool finish(QNetworkReply *reply, QString *error, int *status) {
    const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (status)
        *status = code;
    if (reply->error() != QNetworkReply::NoError) {
        if (error)
            *error = QString("%1: %2").arg(reply->url().toString(), reply->errorString());
        return false;
    }
    return true;
}

} // namespace

QByteArray get(const QUrl &url, QString *error, int *status) {
    QNetworkAccessManager manager;
    QNetworkReply *reply = manager.get(request(url));
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    QByteArray body;
    if (finish(reply, error, status))
        body = reply->readAll();
    reply->deleteLater();
    return body;
}

bool download(const QUrl &url, const QString &path, QString *error, int *status) {
    QFile file(path + ".part");
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error)
            *error = "Could not write " + file.fileName();
        return false;
    }
    QNetworkAccessManager manager;
    QNetworkReply *reply = manager.get(request(url));
    bool writeFailed = false;
    QObject::connect(reply, &QNetworkReply::readyRead, reply, [&] {
        if (file.write(reply->readAll()) < 0 && !writeFailed) {
            writeFailed = true;
            reply->abort();
        }
    });
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    file.write(reply->readAll());
    file.close();
    const bool ok = finish(reply, error, status) && !writeFailed;
    reply->deleteLater();
    if (writeFailed && error)
        *error = "Could not write " + file.fileName() + " (is the disk full?)";
    if (!ok) {
        file.remove();
        return false;
    }
    QFile::remove(path);
    if (!file.rename(path)) {
        if (error)
            *error = "Could not rename " + file.fileName();
        return false;
    }
    return true;
}

} // namespace Net
