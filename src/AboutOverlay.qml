import QtQuick
import QtQuick.Controls

// The About card, the same in every app: the logo, the name as a wide
// wordmark like Fathom's, what the app is for, and whose idea it was.
// Its edge and wordmark keep Fathom's cyan and violet whatever the theme,
// since they're the brand; the rest follows the theme like the window.
Rectangle {
    id: about
    property string appName
    property string purpose
    property string repository   // "github.com/owner/name", or empty
    signal dismissed()
    readonly property real u: theme.fontScale !== undefined ? theme.fontScale : 1
    readonly property color cyan: "#4cc9f0"
    readonly property color violet: "#9d8cff"

    anchors.fill: parent
    color: Qt.rgba(0, 0, 0, 0.6)
    z: 100

    MouseArea { anchors.fill: parent; onClicked: about.dismissed() }

    // A 1.5 px gradient edge: the gradient fills the outer rectangle and
    // the card sits inside it.
    Rectangle {
        id: edge
        anchors.centerIn: parent
        width: Math.min(parent.width - 32, Math.round(440 * about.u))
        height: card.implicitHeight + 3
        radius: theme.radius
        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0; color: about.cyan }
            GradientStop { position: 1; color: about.violet }
        }
        MouseArea { anchors.fill: parent } // a click on the card keeps it open

        Rectangle {
            id: card
            anchors.fill: parent
            anchors.margins: 1.5
            radius: Math.max(0, theme.radius - 1.5)
            color: theme.panel
            implicitHeight: column.implicitHeight + Math.round(64 * about.u)

            Column {
                id: column
                anchors.centerIn: parent
                width: parent.width - Math.round(56 * about.u)
                spacing: Math.round(10 * about.u)

                Image {
                    anchors.horizontalCenter: parent.horizontalCenter
                    source: "qrc:/icon.svg"
                    width: Math.round(88 * about.u)
                    height: width
                    sourceSize: Qt.size(width * 2, height * 2)
                    smooth: true
                }
                Item { width: 1; height: Math.round(4 * about.u) }
                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: about.appName.toUpperCase()
                    color: about.cyan
                    font.pixelSize: Math.round(30 * about.u)
                    font.weight: Font.Medium
                    font.letterSpacing: Math.round(9 * about.u)
                    // Letter spacing trails the last letter too; pull the
                    // word back so it centres.
                    leftPadding: font.letterSpacing
                }
                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: qsTr("Version %1").arg(Qt.application.version)
                    color: theme.muted
                    font.pixelSize: Math.round(12 * about.u)
                }
                Label {
                    width: parent.width
                    text: about.purpose
                    color: theme.text
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    font.pixelSize: Math.round(14 * about.u)
                    lineHeight: 1.15
                }
                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: parent.width * 0.6
                    height: 1
                    gradient: Gradient {
                        orientation: Gradient.Horizontal
                        GradientStop { position: 0; color: "transparent" }
                        GradientStop { position: 0.3; color: about.cyan }
                        GradientStop { position: 0.7; color: about.violet }
                        GradientStop { position: 1; color: "transparent" }
                    }
                }
                Label {
                    width: parent.width
                    text: qsTr("An idea by Alan Seunarayan, developed with AI")
                    color: theme.text
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    font.pixelSize: Math.round(13 * about.u)
                    font.weight: Font.DemiBold
                }
                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: qsTr("MIT licence")
                    color: theme.muted
                    font.pixelSize: Math.round(12 * about.u)
                }
                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    visible: about.repository !== ""
                    text: about.repository
                    color: link.containsMouse ? about.violet : about.cyan
                    font.pixelSize: Math.round(12 * about.u)
                    font.underline: link.containsMouse
                    MouseArea {
                        id: link
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: Qt.openUrlExternally("https://" + about.repository)
                    }
                }
                Item { width: 1; height: Math.round(4 * about.u) }
                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: qsTr("Press Esc or click outside to close")
                    color: theme.muted
                    font.pixelSize: Math.round(11 * about.u)
                }
            }
        }
    }
}
