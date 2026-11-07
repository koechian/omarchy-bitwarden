import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

ColumnLayout {
  id: searchHeaderRoot

  property alias searchQuery: searchInputField.text
  property alias searchField: searchInputField
  property alias categoryTabBar: catBar
  property var categoryList: ["all", "login", "card", "identity", "note"]
  property string activeCategory: "all"
  property var rawVaultItems: []
  property color background: Commons.Color.menu.background
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color borderColor: Commons.Color.menu.border
  property string fontFamily: ""
  property bool modalsActive: false

  property string activeVaultScope: "all"
  property string activeFolderScope: "all"

  signal categorySelected(string category)
  signal vaultScopeSelected(string scope)
  signal folderScopeSelected(string scope)
  signal clearSearchRequested()
  signal copyUsernameRequested()
  signal copyTotpRequested()
  signal openUrlRequested()
  signal actionPaletteRequested()

  property alias isScopeDropdownOpen: vaultScopeDropdown.isOpen
  property alias isVaultScopeOpen: vaultScopeDropdown.isOpen
  property alias isFolderScopeOpen: folderScopeDropdown.isOpen

  function openVaultScope() {
    if (vaultScopeDropdown.isOpen) {
      vaultScopeDropdown.cycleNext()
    } else {
      vaultScopeDropdown.open()
    }
  }

  function openFolderScope() {
    if (folderScopeDropdown.isOpen) {
      folderScopeDropdown.cycleNext()
    } else {
      folderScopeDropdown.open()
    }
  }

  function closeScopeDropdowns() {
    vaultScopeDropdown.close()
    folderScopeDropdown.close()
  }

  function computeVaultScopes() {
    var items = searchHeaderRoot.rawVaultItems || []
    var personalCount = 0
    var orgMap = {}
    for (var i = 0; i < items.length; i++) {
      var it = items[i]
      if (!it.organization_id) {
        personalCount++
      } else {
        var orgId = it.organization_id
        var orgName = it.organization_name || "Organization"
        if (!orgMap[orgId]) {
          orgMap[orgId] = { id: orgId, name: orgName, icon: "\uf1ad", count: 0 }
        }
        orgMap[orgId].count++
      }
    }

    var list = [
      { id: "all", name: "All Vaults", icon: "\uf009", count: items.length },
      { id: "personal", name: "Personal", icon: "\uf007", count: personalCount }
    ]

    var orgKeys = Object.keys(orgMap)
    orgKeys.sort(function(a, b) {
      return orgMap[a].name.localeCompare(orgMap[b].name)
    })

    for (var k = 0; k < orgKeys.length; k++) {
      list.push(orgMap[orgKeys[k]])
    }

    return list
  }

  function computeFolderScopes() {
    var items = searchHeaderRoot.rawVaultItems || []
    var noFolderCount = 0
    var folderMap = {}
    for (var i = 0; i < items.length; i++) {
      var it = items[i]
      if (!it.folder_id && !it.folder_name) {
        noFolderCount++
      } else {
        var fId = it.folder_id || it.folder_name
        var fName = it.folder_name || "Folder"
        if (!folderMap[fId]) {
          folderMap[fId] = { id: fId, name: fName, icon: "\uf07b", count: 0 }
        }
        folderMap[fId].count++
      }
    }

    var list = [
      { id: "all", name: "All Folders", icon: "\uf07b", count: items.length }
    ]

    if (noFolderCount > 0) {
      list.push({ id: "none", name: "No Folder", icon: "\uf016", count: noFolderCount })
    }

    var folderKeys = Object.keys(folderMap)
    folderKeys.sort(function(a, b) {
      return folderMap[a].name.localeCompare(folderMap[b].name)
    })

    for (var j = 0; j < folderKeys.length; j++) {
      list.push(folderMap[folderKeys[j]])
    }

    return list
  }

  function focusSearch(cursorAtEnd) {
    searchInputField.forceActiveFocus()
    if (cursorAtEnd && searchInputField.text.length > 0) {
      searchInputField.cursorPosition = searchInputField.text.length
      searchInputField.deselect()
    }
  }

  // Alt+V / Alt+F open the scope dropdowns. Returns true when handled.
  function handleScopeShortcut(event) {
    var letter = event.text ? event.text.toLowerCase() : ""
    if (event.key === Qt.Key_V || letter === "v") {
      searchHeaderRoot.openVaultScope()
      return true
    }
    if (event.key === Qt.Key_F || letter === "f") {
      searchHeaderRoot.openFolderScope()
      return true
    }
    return false
  }

  // Ctrl+<key> -> the request it emits.
  function controlShortcutRequest(key) {
    var requests = {}
    requests[Qt.Key_Return] = function() { searchHeaderRoot.copyTotpRequested() }
    requests[Qt.Key_Enter] = requests[Qt.Key_Return]
    requests[Qt.Key_U] = function() { searchHeaderRoot.copyUsernameRequested() }
    requests[Qt.Key_O] = function() { searchHeaderRoot.openUrlRequested() }
    requests[Qt.Key_K] = function() { searchHeaderRoot.actionPaletteRequested() }
    return requests[key] || null
  }

  // A held chord is accepted but not repeated: Ctrl+Enter copies a TOTP code,
  // a budgeted release, and must not drain the release budget.
  function handleControlShortcut(event) {
    var request = searchHeaderRoot.controlShortcutRequest(event.key)
    if (!request) return false
    if (!event.isAutoRepeat) request()
    return true
  }

  // Esc in the search field: close an open dropdown, then clear the query,
  // then clear the scope filters. Returns true when handled.
  function handleEscapeKey() {
    if (vaultScopeDropdown.isOpen) {
      vaultScopeDropdown.close()
      return true
    }
    if (folderScopeDropdown.isOpen) {
      folderScopeDropdown.close()
      return true
    }
    if (searchInputField.text.length > 0) {
      searchInputField.text = ""
      searchHeaderRoot.clearSearchRequested()
      return true
    }
    if (searchHeaderRoot.activeVaultScope === "all" && searchHeaderRoot.activeFolderScope === "all") return false
    searchHeaderRoot.vaultScopeSelected("all")
    searchHeaderRoot.folderScopeSelected("all")
    return true
  }

  spacing: 6
  Layout.fillWidth: true

  onVisibleChanged: {
    if (visible) {
      Qt.callLater(function() {
        focusSearch(true)
      })
    }
  }

  // 1. Search Box Bar
  Rectangle {
    Layout.fillWidth: true
    height: 34
    radius: 6
    color: Qt.rgba(searchHeaderRoot.foreground.r, searchHeaderRoot.foreground.g, searchHeaderRoot.foreground.b, 0.08)
    border.color: searchInputField.activeFocus ? searchHeaderRoot.accent : searchHeaderRoot.borderColor
    border.width: 1

    RowLayout {
      anchors.fill: parent
      anchors.leftMargin: 6
      anchors.rightMargin: 6
      spacing: 6

      // Vault / Organization Scope Dropdown (Replaces static magnifying glass)
      ScopeDropdown {
        id: vaultScopeDropdown
        title: "Vault"
        currentValue: searchHeaderRoot.activeVaultScope
        items: searchHeaderRoot.computeVaultScopes()
        foreground: searchHeaderRoot.foreground
        accent: searchHeaderRoot.accent
        borderColor: searchHeaderRoot.borderColor
        fontFamily: searchHeaderRoot.fontFamily
        maxLabelWidth: 120
        Layout.alignment: Qt.AlignVCenter
        onSelected: function(id) {
          searchHeaderRoot.vaultScopeSelected(id)
          searchHeaderRoot.focusSearch()
        }
        onResetRequested: {
          searchHeaderRoot.vaultScopeSelected("all")
          searchHeaderRoot.focusSearch()
        }
        onClosed: {
          searchHeaderRoot.focusSearch()
        }
      }

      Item {
        Layout.fillWidth: true
        Layout.fillHeight: true

        TextInput {
          id: searchInputField
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          color: searchHeaderRoot.foreground
          font.family: "sans-serif"
          font.pixelSize: Style.font.body
          selectByMouse: true
          clip: true

          Keys.priority: Keys.BeforeItem
          Keys.onPressed: function(event) {
            if (searchHeaderRoot.modalsActive) return
            if ((event.modifiers & Qt.AltModifier) && searchHeaderRoot.handleScopeShortcut(event)) {
              event.accepted = true
            } else if ((event.modifiers & Qt.ControlModifier) && searchHeaderRoot.handleControlShortcut(event)) {
              event.accepted = true
            } else if (event.key === Qt.Key_Escape && searchHeaderRoot.handleEscapeKey()) {
              event.accepted = true
            }
          }
        }

        Text {
          textFormat: Text.PlainText
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: "Search Bitwarden vault (names, usernames, URLs, folders)..."
          color: searchHeaderRoot.muted
          font.family: "sans-serif"
          font.pixelSize: Style.font.body
          visible: !searchInputField.text
        }
      }

      // Clear search button (placed before Folder Scope Dropdown)
      Text {
        textFormat: Text.PlainText
        visible: Boolean(searchInputField.text)
        text: "\uf00d"
        font.family: searchHeaderRoot.fontFamily
        color: clearMouse.containsMouse ? searchHeaderRoot.foreground : searchHeaderRoot.muted
        font.pixelSize: Style.font.bodySmall
        Layout.alignment: Qt.AlignVCenter

        MouseArea {
          id: clearMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: {
            searchInputField.text = ""
            searchHeaderRoot.clearSearchRequested()
            searchInputField.forceActiveFocus()
          }
        }
      }

      // Folder Scope Dropdown
      ScopeDropdown {
        id: folderScopeDropdown
        title: "Folder"
        currentValue: searchHeaderRoot.activeFolderScope
        items: searchHeaderRoot.computeFolderScopes()
        foreground: searchHeaderRoot.foreground
        accent: searchHeaderRoot.accent
        borderColor: searchHeaderRoot.borderColor
        fontFamily: searchHeaderRoot.fontFamily
        alignRight: true
        maxLabelWidth: 110
        Layout.alignment: Qt.AlignVCenter
        onSelected: function(id) {
          searchHeaderRoot.folderScopeSelected(id)
          searchHeaderRoot.focusSearch()
        }
        onResetRequested: {
          searchHeaderRoot.folderScopeSelected("all")
          searchHeaderRoot.focusSearch()
        }
        onClosed: {
          searchHeaderRoot.focusSearch()
        }
      }
    }
  }

  // 2. Category Tab Bar & Action Buttons
  RowLayout {
    Layout.fillWidth: true
    spacing: 8

    CategoryTabBar {
      id: catBar
      categoryList: searchHeaderRoot.categoryList
      activeCategory: searchHeaderRoot.activeCategory
      activeVaultScope: searchHeaderRoot.activeVaultScope
      activeFolderScope: searchHeaderRoot.activeFolderScope
      rawVaultItems: searchHeaderRoot.rawVaultItems
      foreground: searchHeaderRoot.foreground
      accent: searchHeaderRoot.accent
      muted: searchHeaderRoot.muted
      borderColor: searchHeaderRoot.borderColor
      onCategorySelected: function(cat) {
        searchHeaderRoot.categorySelected(cat)
      }
    }

    Item { Layout.fillWidth: true }
  }
}
