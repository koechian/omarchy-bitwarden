import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons
import "./VaultSearch.js" as VaultSearch

RowLayout {
  id: tabRoot

  property var categoryList: ["all", "recent", "login", "card", "identity", "note"]
  property string activeCategory: "all"
  property var rawVaultItems: []
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color borderColor: Commons.Color.menu.border

  signal categorySelected(string category)

  spacing: 4

  property string activeVaultScope: "all"
  property string activeFolderScope: "all"

  function getCategoryLabel(cat) {
    switch (cat) {
      case "all": return "All"
      case "recent": return "Recent"
      case "login": return "Logins"
      case "card": return "Cards"
      case "identity": return "Identities"
      case "note": return "Secure Note"
      default: return cat
    }
  }

  // Items of the category inside the active vault and folder scopes, by the
  // same scope rules as the item list.
  function getCategoryCount(cat) {
    var filters = { vaultScope: tabRoot.activeVaultScope, folderScope: tabRoot.activeFolderScope, category: cat }
    return (tabRoot.rawVaultItems || []).filter(function(item) {
      return VaultSearch.matchesFilters(item, filters)
    }).length
  }

  Repeater {
    model: tabRoot.categoryList

    Rectangle {
      id: tabItem
      property string cat: modelData
      property bool isSelected: tabRoot.activeCategory === cat

      implicitHeight: 24
      implicitWidth: tabRow.implicitWidth + 14
      radius: 4
      color: isSelected ? Qt.rgba(tabRoot.accent.r, tabRoot.accent.g, tabRoot.accent.b, 0.2) : (tabMouse.containsMouse ? Qt.rgba(tabRoot.foreground.r, tabRoot.foreground.g, tabRoot.foreground.b, 0.08) : "transparent")
      border.color: isSelected ? tabRoot.accent : "transparent"
      border.width: 1

      RowLayout {
        id: tabRow
        anchors.centerIn: parent
        spacing: 4

        Text {
          textFormat: Text.PlainText
          text: tabRoot.getCategoryLabel(cat)
          color: isSelected ? tabRoot.accent : (tabMouse.containsMouse ? tabRoot.foreground : tabRoot.muted)
          font.pixelSize: Style.font.bodySmall
          font.weight: isSelected ? Font.DemiBold : Font.Normal
        }

        Text {
          textFormat: Text.PlainText
          property int count: tabRoot.getCategoryCount(cat)
          visible: count > 0
          text: count
          color: isSelected ? tabRoot.accent : tabRoot.muted
          font.pixelSize: Style.font.caption
        }
      }

      MouseArea {
        id: tabMouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: tabRoot.categorySelected(cat)
      }
    }
  }
}
