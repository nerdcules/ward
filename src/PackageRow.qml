import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// One package in the list: its name and version, how many CVEs match it, and
// pills for what triage rated "now" or "soon".
Rectangle {
    id: row
    property var entry
    property bool selected: false
    signal clicked()

    implicitHeight: 52
    radius: Math.min(4, theme.radius)
    color: selected ? Qt.rgba(1, 1, 1, 0.07) : mouse.containsMouse ? Qt.rgba(1, 1, 1, 0.03) : "transparent"
    border.color: selected ? theme.accent : "transparent"
    border.width: 1

    MouseArea { id: mouse; anchors.fill: parent; hoverEnabled: true; onClicked: row.clicked() }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 12
        anchors.rightMargin: 12
        spacing: 8

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Label { Layout.fillWidth: true; text: row.entry.package; color: theme.text; font.pixelSize: 14; elide: Text.ElideRight }
            Label {
                Layout.fillWidth: true
                text: row.entry.layer === "project" ? qsTr("project · %1").arg(row.entry.location)
                    : row.entry.layer === "docker" ? qsTr("Docker image")
                    : row.entry.layer === "firmware" ? qsTr("firmware %1").arg(row.entry.version)
                    : row.entry.updateTo !== "" ? qsTr("%1 · fix waiting: %2").arg(row.entry.version).arg(row.entry.updateTo)
                    : row.entry.version
                color: row.entry.updateTo !== "" ? theme.good : theme.muted
                font.pixelSize: 12
                elide: row.entry.layer === "project" ? Text.ElideMiddle : Text.ElideRight
            }
        }
        StatusPill { visible: row.entry.now > 0; text: qsTr("%n now", "", row.entry.now); color: theme.bad; foreground: "black" }
        StatusPill { visible: row.entry.soon > 0; text: qsTr("%n soon", "", row.entry.soon); color: theme.warn; foreground: "black" }
        StatusPill { visible: row.entry.kev > 0; text: qsTr("exploited"); color: theme.panelBorder; foreground: theme.bad }
        Label {
            text: qsTr("%n CVEs", "", row.entry.count)
            color: theme.muted
            font.pixelSize: 12
            horizontalAlignment: Text.AlignRight
            Layout.preferredWidth: 70
        }
    }
}
