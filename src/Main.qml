import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

ApplicationWindow {
    id: win
    width: 1180
    height: 760
    minimumWidth: 860
    minimumHeight: 520
    visible: true
    title: "Ward"
    color: theme.window

    Material.theme: Material.Dark
    Material.accent: theme.accent
    Material.roundedScale: theme.radius

    property bool helpVisible: false
    property bool aboutVisible: false
    property string confirmCommand: ""
    readonly property bool overlayOpen: aboutVisible || helpVisible || confirmCommand !== ""
    readonly property var summary: backend.summary
    readonly property var current: packages.currentIndex >= 0 && packages.currentIndex < backend.packages.length
                                   ? backend.packages[packages.currentIndex] : null
    // Re-read whenever the results or the selection change.
    readonly property var detail: { backend.packages; return current ? backend.detail(current.group) : ({}) }
    readonly property var cves: { backend.packages; return current ? backend.findings(current.group) : [] }
    readonly property var currentCve: cveList.currentIndex >= 0 && cveList.currentIndex < cves.length ? cves[cveList.currentIndex] : null

    function move(list, count, delta) {
        if (count === 0) return
        list.currentIndex = Math.max(0, Math.min(count - 1, list.currentIndex + delta))
        list.positionViewAtIndex(list.currentIndex, ListView.Contain)
    }
    function closeOverlays() { aboutVisible = false; helpVisible = false; confirmCommand = "" }
    function ask(command) { if (command !== "") confirmCommand = command }

    // Nothing in the window is unsaved work, so Q leaves at once.
    Shortcut { sequence: "Ctrl+I"; context: Qt.ApplicationShortcut; onActivated: win.aboutVisible = !win.aboutVisible }
    Shortcut { sequence: "?"; context: Qt.ApplicationShortcut; onActivated: win.helpVisible = !win.helpVisible }
    Shortcut { sequence: "Escape"; context: Qt.ApplicationShortcut; enabled: win.overlayOpen; onActivated: win.closeOverlays() }
    Shortcut { sequence: "Q"; context: Qt.ApplicationShortcut; onActivated: Qt.quit() }
    Shortcut { sequences: ["Space", "R"]; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen; onActivated: backend.check() }
    Shortcut { sequences: ["J", "Down"]; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen; onActivated: { win.move(packages, backend.packages.length, 1); cveList.currentIndex = 0 } }
    Shortcut { sequences: ["K", "Up"]; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen; onActivated: { win.move(packages, backend.packages.length, -1); cveList.currentIndex = 0 } }
    Shortcut { sequence: "N"; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen; onActivated: win.move(cveList, win.cves.length, 1) }
    Shortcut { sequence: "P"; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen; onActivated: win.move(cveList, win.cves.length, -1) }
    Shortcut { sequence: "O"; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen && win.currentCve !== null; onActivated: backend.openCve(win.currentCve.cve) }
    Shortcut { sequence: "U"; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen && win.current !== null; onActivated: win.ask(backend.updateCommand(win.current.group)) }
    Shortcut { sequence: "M"; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen && win.current !== null; onActivated: win.ask(backend.mitigationCommand(win.current.group)) }
    Shortcut { sequence: "F"; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen; onActivated: { backend.attentionOnly = !backend.attentionOnly; packages.currentIndex = 0 } }
    Shortcut { sequence: "T"; context: Qt.ApplicationShortcut; enabled: !win.overlayOpen; onActivated: backend.setScheduled(!backend.scheduled) }

    // Right-to-left languages mirror the window; the Translator sets the
    // application's layout direction.
    Item {
        anchors.fill: parent
        LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
        LayoutMirroring.childrenInherit: true

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 12

            RowLayout {
                Layout.fillWidth: true
                spacing: 16
                Label { text: "Ward"; color: theme.text; font.pixelSize: 20; font.weight: Font.DemiBold }
                Label {
                    Layout.fillWidth: true
                    // Reads translator.language so the date re-renders on a switch.
                    text: {
                        translator.language
                        if (backend.checking)
                            return backend.progress !== "" ? backend.progress : qsTr("Checking…")
                        if (!win.summary.checked)
                            return qsTr("Not checked yet")
                        return qsTr("Checked %1").arg(win.summary.checkedAt.toLocaleString(Qt.locale(), Locale.ShortFormat))
                    }
                    color: theme.muted
                    font.pixelSize: 13
                    elide: Text.ElideRight
                }
                StatusPill {
                    visible: win.summary.checked && win.summary.now > 0
                    text: qsTr("%n need you now", "", win.summary.now)
                    color: theme.bad
                    foreground: "black"
                }
                StatusPill {
                    text: backend.scheduled ? qsTr("Daily check on") : backend.schedulable ? qsTr("Daily check off") : qsTr("Timer not installed")
                    color: backend.scheduled ? theme.good : theme.panelBorder
                    foreground: backend.scheduled ? "black" : theme.muted
                }
            }

            // The kernel's branch, when kernel.org has stopped fixing it: the
            // one finding that no package update in the list can clear.
            Rectangle {
                Layout.fillWidth: true
                visible: win.summary.checked && win.summary.kernelNote !== ""
                implicitHeight: kernelLabel.implicitHeight + 20
                color: Qt.rgba(0.96, 0.77, 0.26, 0.10)
                border.color: theme.warn
                border.width: 1
                radius: theme.radius
                Label {
                    id: kernelLabel
                    anchors.fill: parent
                    anchors.margins: 10
                    text: win.summary.kernelNote
                    color: theme.text
                    font.pixelSize: 13
                    wrapMode: Text.Wrap
                }
            }

            Label {
                Layout.fillWidth: true
                visible: win.summary.checked
                text: {
                    translator.language
                    var s = win.summary
                    var where = [qsTr("%1 of %2 installed packages").arg(Number(s.packages).toLocaleString(Qt.locale(), 'f', 0))
                                     .arg(Number(s.installed).toLocaleString(Qt.locale(), 'f', 0))]
                    if (s.projects > 0) where.push(qsTr("%n projects", "", s.projects))
                    if (s.images > 0) where.push(qsTr("%n Docker images", "", s.images))
                    if (s.devices > 0) where.push(qsTr("%n devices", "", s.devices))
                    return qsTr("%1 CVEs in %2 · now: %3 · soon: %4 · not triaged yet: %5 · known to be exploited: %6")
                        .arg(Number(s.affected).toLocaleString(Qt.locale(), 'f', 0))
                        .arg(where.join(", "))
                        .arg(s.now).arg(s.soon)
                        .arg(Number(s.open).toLocaleString(Qt.locale(), 'f', 0))
                        .arg(s.kev)
                }
                color: theme.muted
                font.pixelSize: 12
                wrapMode: Text.Wrap
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 12

                // ---------------------------------------------- packages
                Rectangle {
                    Layout.preferredWidth: 420
                    Layout.fillHeight: true
                    color: theme.panel
                    radius: theme.radius
                    border.color: theme.panelBorder
                    border.width: 1
                    clip: true

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 6
                        spacing: 4
                        Label {
                            Layout.leftMargin: 8
                            Layout.topMargin: 4
                            text: backend.attentionOnly ? qsTr("What needs a look (F shows everything with a match)") : qsTr("Everything with a match (F for what needs a look)")
                            color: theme.muted
                            font.pixelSize: 12
                        }
                        ListView {
                            id: packages
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            model: backend.packages
                            currentIndex: 0
                            spacing: 2
                            clip: true
                            boundsBehavior: Flickable.StopAtBounds
                            ScrollBar.vertical: ScrollBar {}
                            delegate: PackageRow {
                                width: packages.width
                                entry: modelData
                                selected: ListView.isCurrentItem
                                onClicked: { packages.currentIndex = index; cveList.currentIndex = 0 }
                            }
                            Label {
                                anchors.centerIn: parent
                                width: parent.width - 32
                                visible: backend.packages.length === 0
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.Wrap
                                text: !win.summary.checked
                                      ? qsTr("No check yet. Press Space to check. The first one downloads CVE.org's full list once (669 MB) and keeps a 442 MB copy.")
                                      : qsTr("Nothing needs a look. Press F to see every package with a match.")
                                color: theme.muted
                            }
                        }
                    }
                }

                // ---------------------------------------------- the package
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: theme.panel
                    radius: theme.radius
                    border.color: theme.panelBorder
                    border.width: 1
                    clip: true

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8
                        visible: win.current !== null

                        RowLayout {
                            Layout.fillWidth: true
                            Label { text: win.detail.package || ""; color: theme.text; font.pixelSize: 18; font.weight: Font.DemiBold }
                            Label {
                                text: win.detail.layer === "project" ? qsTr("project in %1").arg(win.detail.location)
                                    : win.detail.layer === "docker" ? qsTr("Docker image")
                                    : win.detail.layer === "firmware" ? qsTr("firmware %1").arg(win.detail.version)
                                    : (win.detail.version || "")
                                color: theme.muted
                                font.pixelSize: 14
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                            Item { Layout.fillWidth: true }
                        }
                        Label {
                            Layout.fillWidth: true
                            visible: (win.detail.exposure || "") !== ""
                            text: qsTr("On this machine: %1").arg(win.detail.exposure || "")
                            color: theme.muted
                            font.pixelSize: 12
                            wrapMode: Text.Wrap
                            maximumLineCount: 3
                            elide: Text.ElideRight
                        }
                        Label {
                            Layout.fillWidth: true
                            text: win.detail.layer === "project"
                                  ? qsTr("Fix it in the project: update each dependency below to the version its CVE names.")
                                  : win.detail.layer === "docker"
                                  ? qsTr("Fix it in the image: rebuild it, or pull a newer one, so its packages reach the fixed versions below.")
                                  : (win.detail.updateTo || "") !== "" && win.detail.layer === "firmware"
                                  ? qsTr("A fixing firmware release is available (%1). Press U to install it with fwupdmgr.").arg(win.detail.updateTo)
                                  : (win.detail.updateTo || "") !== ""
                                  ? qsTr("A fixing update is waiting in the repos (%1). Press U to install it.").arg(win.detail.updateTo)
                                  : (win.detail.fixAll || "") !== ""
                                    ? qsTr("No fixed package in the repos yet. Fixed upstream in %1.").arg(win.detail.fixAll)
                                    : qsTr("No fixed package in the repos yet, and no fixed version named upstream.")
                            color: (win.detail.updateTo || "") !== "" ? theme.good : theme.text
                            font.pixelSize: 13
                            wrapMode: Text.Wrap
                        }
                        Label {
                            Layout.fillWidth: true
                            visible: (win.detail.mitigation || "") !== ""
                            text: qsTr("Claude suggests until then: %1 (M runs it after asking)").arg(win.detail.mitigation || "")
                            color: theme.text
                            font.pixelSize: 13
                            wrapMode: Text.Wrap
                        }

                        ListView {
                            id: cveList
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            Layout.topMargin: 4
                            model: win.cves
                            currentIndex: 0
                            spacing: 2
                            clip: true
                            boundsBehavior: Flickable.StopAtBounds
                            ScrollBar.vertical: ScrollBar {}
                            delegate: FindingRow {
                                width: cveList.width
                                finding: modelData
                                selected: ListView.isCurrentItem
                                onClicked: cveList.currentIndex = index
                            }
                        }
                    }
                }
            }

            Label {
                Layout.fillWidth: true
                visible: text.length > 0
                text: backend.error.length > 0 ? backend.error : backend.notice
                color: backend.error.length > 0 ? theme.bad : theme.text
                font.pixelSize: 13
                elide: Text.ElideRight
            }
            Label {
                Layout.fillWidth: true
                text: qsTr("Space check · J/K packages · N/P CVEs · O open CVE · U update · M mitigation · F filter · T daily check · ? keys · Q quit")
                color: theme.muted
                font.pixelSize: 12
                elide: Text.ElideRight
            }
        }

        ConfirmOverlay {
            anchors.fill: parent
            visible: win.confirmCommand !== ""
            message: qsTr("Run this in a terminal?\n\n%1").arg(win.confirmCommand)
            acceptText: qsTr("Run")
            onClosed: win.confirmCommand = ""
            onAccepted: { backend.runInTerminal(win.confirmCommand); win.confirmCommand = "" }
        }
        HelpOverlay {
            anchors.fill: parent
            visible: win.helpVisible
            onClosed: win.helpVisible = false
        }
    }

    AboutOverlay {
        visible: win.aboutVisible
        appName: "ward"
        purpose: qsTr("Says which published CVEs affect this machine, and which of them matter here")
        repository: "github.com/nerdcules/ward"
        onDismissed: win.aboutVisible = false
    }
}
