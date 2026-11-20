import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

// A yes-or-no question over the window. Enter accepts, Esc or a click
// outside closes.
Rectangle {
    id: overlay
    property string message
    property string acceptText: qsTr("OK")
    signal accepted()
    signal closed()
    color: Qt.rgba(0, 0, 0, 0.6)

    Shortcut { sequences: ["Return", "Enter", "Y"]; context: Qt.ApplicationShortcut; enabled: overlay.visible; onActivated: overlay.accepted() }
    MouseArea { anchors.fill: parent; onClicked: overlay.closed() }

    Rectangle {
        anchors.centerIn: parent
        width: Math.min(460, overlay.width - 48)
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
            spacing: 16
            Label { Layout.fillWidth: true; text: overlay.message; color: theme.text; font.pixelSize: 16; wrapMode: Text.Wrap }
            RowLayout {
                Layout.alignment: Qt.AlignRight
                spacing: 8
                Button { text: qsTr("Cancel"); flat: true; Material.roundedScale: theme.radius; onClicked: overlay.closed() }
                Button { text: overlay.acceptText; highlighted: true; Material.background: theme.accent; Material.foreground: theme.accentForeground; Material.roundedScale: theme.radius; onClicked: overlay.accepted() }
            }
        }
    }
}
