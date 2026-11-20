import QtQuick
import QtQuick.Controls

// A small coloured label: a status, a count, the timer state.
Rectangle {
    property alias text: label.text
    property string foreground: "black"
    implicitWidth: label.implicitWidth + 16
    implicitHeight: label.implicitHeight + 8
    radius: Math.min(4, theme.radius)
    Label {
        id: label
        anchors.centerIn: parent
        color: parent.foreground
        font.pixelSize: 12
        font.weight: Font.DemiBold
    }
}
