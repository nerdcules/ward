#pragma once

#include <QStringList>

// Commands that need no display, so the timer, a script or an agent can run
// the same check the window shows. isCliCommand says whether the arguments
// name one; anything else opens the window.
bool isCliCommand(const QStringList &arguments);
int runCli(const QStringList &arguments);
