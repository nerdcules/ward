import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Every shortcut, over the window, until Esc or a click outside.
Rectangle {
    id: overlay
    signal closed()
    color: Qt.rgba(0, 0, 0, 0.6)

    MouseArea { anchors.fill: parent; onClicked: overlay.closed() }

    Rectangle {
        anchors.centerIn: parent
        width: Math.min(600, overlay.width - 48)
        height: column.implicitHeight + 48
        color: theme.panel
        radius: theme.radius
        border.color: theme.panelBorder
        border.width: 1
        MouseArea { anchors.fill: parent }

        ColumnLayout {
            id: column
            anchors.fill: parent
            anchors.margins: 24
            spacing: 12

            Label { text: qsTr("Keyboard"); color: theme.text; font.pixelSize: 18; font.weight: Font.DemiBold }

            Repeater {
                model: [
                    ["Space / R", qsTr("Check now: update the CVE list, match, and triage what is new")],
                    ["J / K, ↓ / ↑", qsTr("Move between packages")],
                    ["N / P", qsTr("Move between the package's CVEs")],
                    ["O", qsTr("Open the selected CVE on cve.org")],
                    ["U", qsTr("Install the waiting update in a terminal (asks first)")],
                    ["M", qsTr("Run Claude's suggested mitigation in a terminal (asks first)")],
                    ["F", qsTr("Show every package, or only those that need a look")],
                    ["T", qsTr("Turn the daily check on or off")],
                    ["?", qsTr("Show or hide this list")],
                    ["Ctrl + I", qsTr("About this app")],
                    ["Q", qsTr("Quit")]
                ]
                delegate: RowLayout {
                    Layout.fillWidth: true
                    spacing: 16
                    Label { Layout.preferredWidth: 120; text: modelData[0]; color: theme.accent; font.family: "monospace"; font.pixelSize: 13 }
                    Label { Layout.fillWidth: true; text: modelData[1]; color: theme.text; font.pixelSize: 13; wrapMode: Text.Wrap }
                }
            }

            Label {
                Layout.fillWidth: true
                text: qsTr("A check runs ward check, as the daily timer does. Triage asks Claude Code, on your account, at most 10 times a check, about up to 25 CVEs of one package each time; answers are kept, so each CVE is asked about once.")
                color: theme.muted
                font.pixelSize: 12
                wrapMode: Text.Wrap
            }
        }
    }
}
