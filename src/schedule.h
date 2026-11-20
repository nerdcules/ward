#pragma once

#include <QString>

// The daily check: ward.timer, a systemd user timer the package installs.
// Turning it on is the user's choice, made in the window (T) or with
// `ward schedule on`.
namespace Schedule {

enum class State { On, Off, NotInstalled };

State state();
// False with the reason in `error`.
bool set(bool on, QString *error);

} // namespace Schedule
