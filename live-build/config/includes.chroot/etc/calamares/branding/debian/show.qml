/* === This file is part of Calamares - <http://github.com/calamares> ===
 *
 *   Copyright 2015, Teo Mrnjavac <teo@kde.org>
 *   Copyright 2018-2019, Jonathan Carter <jcc@debian.org>
 *
 *   Calamares is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, or (at your option) any later version.
 *
 *   Calamares is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Calamares. If not, see <http://www.gnu.org/licenses/>.
 */

import QtQuick 2.15;
import calamares.slideshow 1.0;

Presentation
{
    id: presentation

    Timer {
        interval: 12000
        repeat: true
        onTriggered: presentation.goToNextSlide()
    }

    Slide {
        Rectangle { anchors.fill: parent; color: "#090B0E" }
        Image {
            anchors.fill: parent
            source: "slide-fire.jpg"
            fillMode: Image.PreserveAspectCrop
            opacity: 0.82
        }
        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 116; color: "#E60A0C10" }
        Text {
            anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
            anchors.margins: 24; height: 82
            color: "#FFFFFF"; wrapMode: Text.WordWrap; textFormat: Text.RichText
            font.pixelSize: 17; horizontalAlignment: Text.AlignLeft
            text: qsTr("<b>Shadowfetch Linux 3.5.0</b><br/>Fire keeps connected production work close. Ice starts agent sessions offline. Both retain the same KDE desktop and recovery tools.")
        }
    }

    Slide {
        Rectangle { anchors.fill: parent; color: "#071014" }
        Image {
            anchors.fill: parent
            source: "slide-ice.jpg"
            fillMode: Image.PreserveAspectCrop
            opacity: 0.78
        }
        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 116; color: "#E6070C11" }
        Text {
            anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
            anchors.margins: 24; height: 82
            color: "#FFFFFF"; wrapMode: Text.WordWrap; textFormat: Text.RichText
            font.pixelSize: 17; horizontalAlignment: Text.AlignLeft
            text: qsTr("<b>Element Workbench</b><br/>Create a Software Studio, AI Lab, Production Ops desk or Creative AI workspace. Install only the signed tools you choose.")
        }
    }

    Slide {
        Rectangle { anchors.fill: parent; color: "#090B0E" }
        Image {
            anchors.fill: parent
            source: "slide-fire.jpg"
            fillMode: Image.PreserveAspectCrop
            opacity: 0.68
        }
        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 116; color: "#E60A0C10" }
        Text {
            anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
            anchors.margins: 24; height: 82
            color: "#FFFFFF"; wrapMode: Text.WordWrap; textFormat: Text.RichText
            font.pixelSize: 17; horizontalAlignment: Text.AlignLeft
            text: qsTr("<b>AI with visible boundaries</b><br/>Buzz, local models, Codex, Claude Code, Grok Build and Cursor remain optional. No model, account or credential is bundled or downloaded without consent.")
        }
    }

    Slide {
        Rectangle { anchors.fill: parent; color: "#071014" }
        Image {
            anchors.fill: parent
            source: "slide-ice.jpg"
            fillMode: Image.PreserveAspectCrop
            opacity: 0.68
        }
        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 116; color: "#E6070C11" }
        Text {
            anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
            anchors.margins: 24; height: 82
            color: "#FFFFFF"; wrapMode: Text.WordWrap; textFormat: Text.RichText
            font.pixelSize: 17; horizontalAlignment: Text.AlignLeft
            text: qsTr("<b>Built to come back</b><br/>Fireproof simulates updates first. Phoenix Points protect system changes. Firebreak confines agent writes to the project you select.")
        }
    }

}
