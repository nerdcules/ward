import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// One CVE: its id and score, triage's priority, and the reason, Claude's or
// Ward's, in a sentence.
Rectangle {
    id: row
    property var finding
    property bool selected: false
    signal clicked()

    readonly property bool triaged: finding.applies !== ""
    implicitHeight: column.implicitHeight + 16
    radius: Math.min(4, theme.radius)
    color: selected ? Qt.rgba(1, 1, 1, 0.07) : "transparent"
    border.color: selected ? theme.accent : "transparent"
    border.width: 1

    MouseArea { anchors.fill: parent; onClicked: row.clicked() }

    ColumnLayout {
        id: column
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: 8
        anchors.leftMargin: 12
        anchors.rightMargin: 12
        spacing: 4

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Label { text: row.finding.cve; color: theme.text; font.family: "monospace"; font.pixelSize: 13 }
            Label {
                visible: row.finding.score >= 0
                text: {
                    translator.language
                    return qsTr("score %1").arg(Number(row.finding.score).toLocaleString(Qt.locale(), 'f', 1))
                }
                color: theme.muted
                font.pixelSize: 12
            }
            Item { Layout.fillWidth: true }
            StatusPill { visible: row.finding.kev; text: qsTr("exploited"); color: theme.panelBorder; foreground: theme.bad }
            StatusPill {
                text: !row.triaged ? qsTr("not triaged")
                     : row.finding.priority === "now" ? qsTr("now")
                     : row.finding.priority === "soon" ? qsTr("soon")
                     : row.finding.applies === "no" ? qsTr("doesn't apply") : qsTr("later")
                color: !row.triaged ? theme.panelBorder
                      : row.finding.priority === "now" ? theme.bad
                      : row.finding.priority === "soon" ? theme.warn : theme.panelBorder
                foreground: row.triaged && (row.finding.priority === "now" || row.finding.priority === "soon") ? "black" : theme.muted
            }
        }
        Label {
            Layout.fillWidth: true
            text: row.triaged ? row.finding.why : row.finding.title
            color: row.triaged ? theme.text : theme.muted
            font.pixelSize: 13
            wrapMode: Text.Wrap
            maximumLineCount: row.selected ? 8 : 2
            elide: Text.ElideRight
        }
        Label {
            Layout.fillWidth: true
            visible: text !== ""
            text: {
                var parts = []
                if (row.finding.component !== "") parts.push(row.finding.fixedIn !== ""
                    ? qsTr("%1 %2 → %3").arg(row.finding.component).arg(row.finding.version).arg(row.finding.fixedIn)
                    : qsTr("%1 %2, no fixed version named").arg(row.finding.component).arg(row.finding.version))
                else if (row.finding.fixedIn !== "") parts.push(qsTr("fixed upstream in %1").arg(row.finding.fixedIn))
                if (row.finding.advisory !== "" && row.finding.advisory !== row.finding.cve) parts.push(row.finding.advisory)
                if (row.finding.where !== "") parts.push(qsTr("kernel code: %1").arg(row.finding.where))
                if (row.triaged) parts.push(row.finding.triagedBy === "claude" ? qsTr("judged by Claude") : qsTr("settled by Ward"))
                if (row.finding.match === "name") parts.push(qsTr("matched by name only"))
                return parts.join(" · ")
            }
            color: theme.muted
            font.pixelSize: 11
            elide: Text.ElideRight
        }
    }
}
