import QtQuick 2.15

Rectangle {
    id: root
    color: "#0e1116"
    anchors.fill: parent

    property int stage: 0
    readonly property int totalStages: 6

    Column {
        anchors.centerIn: parent
        spacing: 30

        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: "Shadowfetch"
            color: "#4aa2d8"
            font.family: "Inter"
            font.pixelSize: 46
            font.weight: Font.DemiBold
            font.letterSpacing: 2
            renderType: Text.NativeRendering
        }

        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: "U M B R A"
            color: "#9aa3ad"
            font.family: "Inter"
            font.pixelSize: 14
            font.weight: Font.Medium
            font.letterSpacing: 8
            renderType: Text.NativeRendering
        }

        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            width: 280
            height: 4
            radius: 2
            color: "#262b33"

            Rectangle {
                height: parent.height
                radius: 2
                color: "#4aa2d8"
                width: parent.width * Math.max(0.04, Math.min(1.0, root.stage / root.totalStages))
                Behavior on width {
                    NumberAnimation { duration: 280; easing.type: Easing.OutCubic }
                }
            }
        }
    }
}
