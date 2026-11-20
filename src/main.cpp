// ward - says which published CVEs affect this machine, and which of them
// matter here.

#include <QCoreApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QUrl>

#include "backend.h"
#include "cli.h"
#include "theme.h"
#include "translator.h"

int main(int argc, char *argv[]) {
    // The display-free commands only need an event loop for processes and
    // HTTP, so they skip the GUI stack and work from a timer or over SSH.
    {
        QStringList arguments;
        for (int i = 0; i < argc; ++i)
            arguments.append(QString::fromLocal8Bit(argv[i]));
        if (isCliCommand(arguments)) {
            QCoreApplication app(argc, argv);
            app.setApplicationName("ward");
            app.setApplicationVersion("0.1.0");
            Translator translator;
            app.installTranslator(&translator);
            return runCli(arguments);
        }
    }

    QGuiApplication app(argc, argv);
    app.setApplicationName("ward");
    app.setApplicationVersion("0.1.0");
    // Matches the window to ward.desktop, so the compositor (Wayland app_id)
    // and the launcher pick up the installed icon.
    app.setDesktopFileName("ward");
    app.setWindowIcon(QIcon::fromTheme("ward"));
    QQuickStyle::setStyle("Material");

    Translator translator;
    app.installTranslator(&translator);
    Theme theme;
    Backend backend;

    QQmlApplicationEngine engine;
    QObject::connect(&translator, &Translator::changed, &engine, &QQmlEngine::retranslate);
    engine.rootContext()->setContextProperty("translator", &translator);
    engine.rootContext()->setContextProperty("theme", &theme);
    engine.rootContext()->setContextProperty("backend", &backend);
    engine.load(QUrl("qrc:/Main.qml"));
    if (engine.rootObjects().isEmpty())
        return 1;
    return app.exec();
}
