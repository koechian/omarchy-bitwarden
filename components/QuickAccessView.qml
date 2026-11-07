import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Commons as Commons
import "QuickAccessModel.js" as QuickAccessModel

// Content of the bar dropdown (quick access panel). Three faces:
//   - the list: a search field over the vault's login items, with quick copy
//     buttons on each row (the dropdown closes after a quick copy);
//   - the details page of one login (click a row or press Enter): copy the
//     username, the password or the verification code, or stage the paste
//     sequence (first paste the password, next paste the code); the dropdown
//     stays open, so several values can be copied one after another;
//   - a master password field while the vault is locked.
// The view holds no secrets and runs no commands; it reports what the user
// asked for through its signals and the bar widget carries it out.
FocusScope {
  id: quickAccessRoot

  property string view: QuickAccessModel.VIEW_LOADING
  property var vaultItems: []
  property bool busy: false
  property string errorText: ""
  property string confirmationText: ""
  property string fontFamily: ""
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color urgent: Commons.Color.urgent
  property color selectedBackground: Commons.Color.menu.selectedBackground
  property color borderColor: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.12)
  property int visibleRowLimit: 8

  property string query: ""
  property int selectedIndex: 0
  property var detailItem: null
  readonly property bool showingList: view === QuickAccessModel.VIEW_UNLOCKED && detailItem === null
  readonly property bool showingDetails: view === QuickAccessModel.VIEW_UNLOCKED && detailItem !== null
  readonly property var rankedItems: QuickAccessModel.rankItems(vaultItems, query)
  readonly property var selectedItem: (selectedIndex >= 0 && selectedIndex < rankedItems.length) ? rankedItems[selectedIndex] : null
  readonly property int rowHeight: 46
  readonly property int sectionHeaderHeight: 22
  readonly property int recentCount: QuickAccessModel.recentCount(rankedItems, query)
  readonly property int fieldRowHeight: 44
  readonly property int sectionSpacing: 10
  readonly property string maskedValue: "••••••••••"

  // Page change between the list and the details page: the page that
  // appears fades in while travelling a short way in the reading direction
  // (the details page from the trailing side, the list back from the
  // leading side). Instant when animations are off (Style.duration is 0).
  readonly property int pageTravel: LayoutMirroring.enabled ? -8 : 8
  readonly property int pageChangeDuration: 150
  property real listOpacity: 1
  property real listOffset: 0
  property real detailOpacity: 1
  property real detailOffset: 0

  // closeAfter: true for the quick copies of the list, false on the details page.
  signal copyRequested(var item, string kind, bool closeAfter)
  signal sequenceRequested(var item)
  signal unlockRequested(string password)
  signal openOverlayRequested()
  signal lockRequested()
  signal retryRequested()
  signal closeRequested()

  readonly property QtObject strings: Commons.Translations {
    directory: Qt.resolvedUrl("../i18n")
  }

  implicitWidth: 380
  implicitHeight: layout.implicitHeight

  onRankedItemsChanged: selectedIndex = QuickAccessModel.clampIndex(0, rankedItems.length)
  onViewChanged: {
    if (view !== QuickAccessModel.VIEW_UNLOCKED) detailItem = null
    Qt.callLater(focusInput)
  }
  onVaultItemsChanged: if (detailItem !== null) detailItem = findItem(detailItem.id)
  onActiveFocusChanged: if (activeFocus) focusInput()

  // Clears the master password field. Called the moment the dropdown
  // starts to close, so a master password never outlives the dropdown it
  // was typed into; it changes nothing the closing card shows.
  function clearSecretInput() {
    passwordInput.text = ""
  }

  // Clears what the user typed and returns to the list. Called once the
  // closed dropdown has faded out.
  function reset() {
    clearSecretInput()
    pageEntrance.stop()
    query = ""
    searchInput.text = ""
    selectedIndex = 0
    detailItem = null
    listOpacity = 1
    listOffset = 0
    detailOpacity = 1
    detailOffset = 0
  }

  function playPageEntrance(opacityProperty, offsetProperty, travel) {
    pageEntrance.stop()
    entranceOpacity.property = opacityProperty
    entranceOffset.property = offsetProperty
    entranceOffset.from = travel
    pageEntrance.start()
  }

  function focusInput() {
    if (view === QuickAccessModel.VIEW_LOCKED) passwordInput.forceActiveFocus()
    else if (showingDetails) detailPage.forceActiveFocus()
    else searchInput.forceActiveFocus()
  }

  // The refreshed listing replaces the shown item, or closes the details
  // page when the item is gone.
  function findItem(itemId) {
    for (var i = 0; i < vaultItems.length; i++) {
      if (vaultItems[i] && vaultItems[i].id === itemId) return vaultItems[i]
    }
    return null
  }

  function openDetails(item) {
    if (!item) return
    var entering = detailItem === null
    detailItem = item
    if (entering) playPageEntrance("detailOpacity", "detailOffset", pageTravel)
    Qt.callLater(focusInput)
  }

  function closeDetails() {
    detailItem = null
    playPageEntrance("listOpacity", "listOffset", -pageTravel)
    Qt.callLater(focusInput)
  }

  ParallelAnimation {
    id: pageEntrance
    NumberAnimation {
      id: entranceOpacity
      target: quickAccessRoot
      from: 0
      to: 1
      duration: Style.duration(quickAccessRoot.pageChangeDuration)
      easing.type: Easing.Bezier
      easing.bezierCurve: Style.easeOut
    }
    NumberAnimation {
      id: entranceOffset
      target: quickAccessRoot
      to: 0
      duration: Style.duration(quickAccessRoot.pageChangeDuration)
      easing.type: Easing.Bezier
      easing.bezierCurve: Style.easeOut
    }
  }

  // Section label above a row of the list: "Recent" above the first recent
  // login and "All logins" above the first of the others, while the list
  // has a recent section (no query typed).
  function sectionTitleAt(index) {
    if (recentCount === 0) return ""
    if (index === 0) return strings.t("quickAccess.recentSection", "Recent")
    if (index === recentCount) return strings.t("quickAccess.allSection", "All logins")
    return ""
  }

  // Height of the visible rows, with the section labels among them.
  function listHeight() {
    var rows = Math.min(rankedItems.length, visibleRowLimit)
    var labels = 0
    if (recentCount > 0) labels = 1
    if (recentCount > 0 && recentCount < rows) labels = 2
    return rows * rowHeight + labels * sectionHeaderHeight
  }

  function moveSelection(step) {
    selectedIndex = QuickAccessModel.clampIndex(selectedIndex + step, rankedItems.length)
    if (selectedIndex >= 0) itemList.positionViewAtIndex(selectedIndex, ListView.Contain)
  }

  function requestCopy(item, kind, closeAfter) {
    if (!busy && QuickAccessModel.canCopy(item, kind)) copyRequested(item, kind, closeAfter)
  }

  function requestSequence(item) {
    if (!busy && QuickAccessModel.canCopySequence(item)) sequenceRequested(item)
  }

  function submitUnlock() {
    if (busy || passwordInput.text === "") return
    var password = passwordInput.text
    passwordInput.text = ""
    unlockRequested(password)
  }

  function isEnter(event) {
    return event.key === Qt.Key_Return || event.key === Qt.Key_Enter
  }

  function hasControl(event) {
    return (event.modifiers & Qt.ControlModifier) !== 0
  }

  function hasShift(event) {
    return (event.modifiers & Qt.ShiftModifier) !== 0
  }

  // Shortcuts shared by the list (on the selected item) and the details
  // page: Ctrl+Enter copies the code, Shift+Enter stages the paste sequence,
  // Ctrl+U copies the username, Ctrl+L locks, Ctrl+O opens the full window.
  function handleItemShortcut(event, item, closeAfter) {
    var ctrl = hasControl(event)
    if (isEnter(event) && ctrl) { requestCopy(item, QuickAccessModel.COPY_TOTP, closeAfter); return true }
    if (isEnter(event) && hasShift(event)) { requestSequence(item); return true }
    if (ctrl && event.key === Qt.Key_U) { requestCopy(item, QuickAccessModel.COPY_USERNAME, closeAfter); return true }
    if (ctrl && event.key === Qt.Key_L) { lockRequested(); return true }
    if (ctrl && event.key === Qt.Key_O) { openOverlayRequested(); return true }
    return false
  }

  // List: arrows move the selection and Enter opens the details page.
  function handleSearchKey(event) {
    if (event.key === Qt.Key_Down) { moveSelection(1); return true }
    if (event.key === Qt.Key_Up) { moveSelection(-1); return true }
    if (handleItemShortcut(event, selectedItem, true)) return true
    if (isEnter(event)) { openDetails(selectedItem); return true }
    return false
  }

  // Details page: Enter copies the password; Escape, Backspace and Left
  // return to the list.
  function handleDetailKey(event) {
    if (handleItemShortcut(event, detailItem, false)) return true
    if (isEnter(event)) { requestCopy(detailItem, QuickAccessModel.primaryCopyKind(detailItem), false); return true }
    if (event.key === Qt.Key_Escape || event.key === Qt.Key_Backspace || event.key === Qt.Key_Left) { closeDetails(); return true }
    return false
  }

  Keys.onEscapePressed: closeRequested()

  component FieldRow: Rectangle {
    id: fieldRow
    property string label: ""
    property string value: ""
    property string copyKind: ""
    property string glyph: ""
    readonly property bool available: QuickAccessModel.canCopy(quickAccessRoot.detailItem, copyKind)
    visible: available
    width: parent ? parent.width : 0
    height: quickAccessRoot.fieldRowHeight
    radius: Style.cornerRadius
    color: fieldMouse.containsMouse ? quickAccessRoot.selectedBackground : "transparent"

    MouseArea {
      id: fieldMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: quickAccessRoot.requestCopy(quickAccessRoot.detailItem, fieldRow.copyKind, false)
    }

    Column {
      anchors.left: parent.left
      anchors.leftMargin: 10
      anchors.right: fieldCopy.left
      anchors.rightMargin: 8
      anchors.verticalCenter: parent.verticalCenter
      spacing: 2

      Text {
        textFormat: Text.PlainText
        text: fieldRow.label
        color: quickAccessRoot.muted
        font.family: quickAccessRoot.fontFamily
        font.pixelSize: Style.font.caption
      }

      Text {
        textFormat: Text.PlainText
        width: parent.width
        elide: Text.ElideRight
        text: fieldRow.value
        color: quickAccessRoot.foreground
        font.family: quickAccessRoot.fontFamily
        font.pixelSize: Style.font.body
      }
    }

    GhostIconButton {
      id: fieldCopy
      anchors.right: parent.right
      anchors.rightMargin: 6
      anchors.verticalCenter: parent.verticalCenter
      iconText: fieldRow.glyph
      fontFamily: quickAccessRoot.fontFamily
      foreground: quickAccessRoot.foreground
      muted: quickAccessRoot.muted
      onClicked: quickAccessRoot.requestCopy(quickAccessRoot.detailItem, fieldRow.copyKind, false)
    }
  }

  Column {
    id: layout
    width: parent.width
    spacing: quickAccessRoot.sectionSpacing

    // --- search (list) ---------------------------------------------------
    Rectangle {
      id: searchBox
      visible: quickAccessRoot.showingList
      opacity: quickAccessRoot.listOpacity
      transform: Translate { x: quickAccessRoot.listOffset }
      width: parent.width
      height: 34
      radius: Style.cornerRadius
      color: "transparent"
      border.width: 1
      border.color: searchInput.activeFocus ? quickAccessRoot.accent : quickAccessRoot.borderColor

      Text {
        id: searchGlyph
        textFormat: Text.PlainText
        anchors.left: parent.left
        anchors.leftMargin: 10
        anchors.verticalCenter: parent.verticalCenter
        text: ""
        color: quickAccessRoot.muted
        font.family: quickAccessRoot.fontFamily
        font.pixelSize: Style.font.bodySmall
      }

      TextInput {
        id: searchInput
        anchors.left: searchGlyph.right
        anchors.leftMargin: 8
        anchors.right: parent.right
        anchors.rightMargin: 10
        anchors.verticalCenter: parent.verticalCenter
        clip: true
        color: quickAccessRoot.foreground
        selectionColor: quickAccessRoot.accent
        font.family: quickAccessRoot.fontFamily
        font.pixelSize: Style.font.body
        onTextChanged: quickAccessRoot.query = text
        Keys.onPressed: function(event) { event.accepted = quickAccessRoot.handleSearchKey(event) }
        Keys.onEscapePressed: quickAccessRoot.closeRequested()

        Text {
          textFormat: Text.PlainText
          anchors.fill: parent
          verticalAlignment: Text.AlignVCenter
          visible: searchInput.text === ""
          text: quickAccessRoot.strings.t("quickAccess.searchPlaceholder", "Search logins")
          color: quickAccessRoot.muted
          font: searchInput.font
        }
      }
    }

    // --- item list (list) ------------------------------------------------
    ListView {
      id: itemList
      visible: quickAccessRoot.showingList && quickAccessRoot.rankedItems.length > 0
      opacity: quickAccessRoot.listOpacity
      transform: Translate { x: quickAccessRoot.listOffset }
      width: parent.width
      height: quickAccessRoot.listHeight()
      clip: true
      boundsBehavior: Flickable.StopAtBounds
      model: quickAccessRoot.rankedItems
      currentIndex: quickAccessRoot.selectedIndex
      ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

      delegate: Item {
        id: row
        required property var modelData
        required property int index
        readonly property bool selected: index === quickAccessRoot.selectedIndex
        readonly property string sectionTitle: quickAccessRoot.sectionTitleAt(index)
        width: itemList.width
        height: quickAccessRoot.rowHeight + (sectionTitle !== "" ? quickAccessRoot.sectionHeaderHeight : 0)

        Text {
          textFormat: Text.PlainText
          visible: row.sectionTitle !== ""
          anchors.left: parent.left
          anchors.leftMargin: 10
          anchors.bottom: rowArea.top
          anchors.bottomMargin: 4
          text: row.sectionTitle
          color: quickAccessRoot.muted
          font.family: quickAccessRoot.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        Rectangle {
          id: rowArea
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.bottom: parent.bottom
          height: quickAccessRoot.rowHeight
          radius: Style.cornerRadius
          color: (row.selected || rowMouse.containsMouse) ? quickAccessRoot.selectedBackground : "transparent"
        }

        MouseArea {
          id: rowMouse
          anchors.fill: rowArea
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onEntered: quickAccessRoot.selectedIndex = row.index
          onClicked: quickAccessRoot.openDetails(row.modelData)
        }

        Column {
          anchors.left: parent.left
          anchors.leftMargin: 10
          anchors.right: actions.left
          anchors.rightMargin: 8
          anchors.verticalCenter: rowArea.verticalCenter
          spacing: 2

          Text {
            textFormat: Text.PlainText
            width: parent.width
            elide: Text.ElideRight
            text: String(row.modelData.name || "")
            color: row.selected ? quickAccessRoot.accent : quickAccessRoot.foreground
            font.family: quickAccessRoot.fontFamily
            font.pixelSize: Style.font.body
            font.bold: true
          }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            elide: Text.ElideRight
            visible: text !== ""
            text: QuickAccessModel.usernameOf(row.modelData)
            color: quickAccessRoot.muted
            font.family: quickAccessRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
        }

        Row {
          id: actions
          anchors.right: parent.right
          anchors.rightMargin: 6
          anchors.verticalCenter: rowArea.verticalCenter
          spacing: 2

          GhostIconButton {
            objectName: "copyUsernameButton"
            visible: QuickAccessModel.canCopy(row.modelData, QuickAccessModel.COPY_USERNAME)
            iconText: ""
            fontFamily: quickAccessRoot.fontFamily
            foreground: quickAccessRoot.foreground
            muted: quickAccessRoot.muted
            onClicked: quickAccessRoot.requestCopy(row.modelData, QuickAccessModel.COPY_USERNAME, true)
          }
          GhostIconButton {
            objectName: "copyPasswordButton"
            visible: QuickAccessModel.canCopy(row.modelData, QuickAccessModel.COPY_PASSWORD)
            iconText: ""
            fontFamily: quickAccessRoot.fontFamily
            foreground: quickAccessRoot.foreground
            muted: quickAccessRoot.muted
            onClicked: quickAccessRoot.requestCopy(row.modelData, QuickAccessModel.COPY_PASSWORD, true)
          }
          GhostIconButton {
            objectName: "copyTotpButton"
            visible: QuickAccessModel.canCopy(row.modelData, QuickAccessModel.COPY_TOTP)
            iconText: ""
            fontFamily: quickAccessRoot.fontFamily
            foreground: quickAccessRoot.foreground
            muted: quickAccessRoot.muted
            onClicked: quickAccessRoot.requestCopy(row.modelData, QuickAccessModel.COPY_TOTP, true)
          }
        }
      }
    }

    // --- details page ------------------------------------------------------
    FocusScope {
      id: detailPage
      visible: quickAccessRoot.showingDetails
      opacity: quickAccessRoot.detailOpacity
      transform: Translate { x: quickAccessRoot.detailOffset }
      width: parent.width
      height: visible ? detailColumn.implicitHeight : 0
      Keys.onPressed: function(event) { event.accepted = quickAccessRoot.handleDetailKey(event) }

      Column {
        id: detailColumn
        width: parent.width
        spacing: 6

        Item {
          width: parent.width
          height: 40

          GhostIconButton {
            id: backButton
            objectName: "backButton"
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            iconText: ""
            fontFamily: quickAccessRoot.fontFamily
            foreground: quickAccessRoot.foreground
            muted: quickAccessRoot.muted
            onClicked: quickAccessRoot.closeDetails()
          }

          Column {
            anchors.left: backButton.right
            anchors.leftMargin: 8
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: 2

            Text {
              textFormat: Text.PlainText
              width: parent.width
              elide: Text.ElideRight
              text: quickAccessRoot.detailItem ? String(quickAccessRoot.detailItem.name || "") : ""
              color: quickAccessRoot.foreground
              font.family: quickAccessRoot.fontFamily
              font.pixelSize: Style.font.subtitle
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              elide: Text.ElideRight
              visible: text !== ""
              text: QuickAccessModel.websiteOf(quickAccessRoot.detailItem)
              color: quickAccessRoot.muted
              font.family: quickAccessRoot.fontFamily
              font.pixelSize: Style.font.bodySmall
            }
          }
        }

        FieldRow {
          objectName: "usernameField"
          label: quickAccessRoot.strings.t("quickAccess.username", "Username")
          value: QuickAccessModel.usernameOf(quickAccessRoot.detailItem)
          copyKind: QuickAccessModel.COPY_USERNAME
          glyph: ""
        }

        FieldRow {
          objectName: "passwordField"
          label: quickAccessRoot.strings.t("quickAccess.password", "Password")
          value: quickAccessRoot.maskedValue
          copyKind: QuickAccessModel.COPY_PASSWORD
          glyph: ""
        }

        FieldRow {
          objectName: "totpField"
          label: quickAccessRoot.strings.t("quickAccess.verificationCode", "Verification code")
          value: quickAccessRoot.strings.t("quickAccess.verificationCodeHidden", "••• •••")
          copyKind: QuickAccessModel.COPY_TOTP
          glyph: ""
        }

        Rectangle {
          id: sequenceButton
          objectName: "sequenceButton"
          visible: QuickAccessModel.canCopySequence(quickAccessRoot.detailItem)
          width: parent.width
          height: 48
          radius: Style.cornerRadius
          color: sequenceMouse.containsMouse ? quickAccessRoot.selectedBackground : "transparent"
          border.width: 1
          border.color: quickAccessRoot.accent

          MouseArea {
            id: sequenceMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: quickAccessRoot.requestSequence(quickAccessRoot.detailItem)
          }

          Column {
            anchors.centerIn: parent
            spacing: 2

            Text {
              textFormat: Text.PlainText
              anchors.horizontalCenter: parent.horizontalCenter
              text: quickAccessRoot.strings.t("quickAccess.sequenceAction", "Copy password, then code")
              color: quickAccessRoot.accent
              font.family: quickAccessRoot.fontFamily
              font.pixelSize: Style.font.body
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              anchors.horizontalCenter: parent.horizontalCenter
              text: quickAccessRoot.strings.t("quickAccess.sequenceHint", "First paste: password · next paste: code")
              color: quickAccessRoot.muted
              font.family: quickAccessRoot.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }
      }
    }

    // --- master password (locked) ----------------------------------------
    Text {
      textFormat: Text.PlainText
      visible: quickAccessRoot.view === QuickAccessModel.VIEW_LOCKED
      width: parent.width
      text: quickAccessRoot.strings.t("quickAccess.lockedTitle", "Bitwarden is locked")
      color: quickAccessRoot.foreground
      font.family: quickAccessRoot.fontFamily
      font.pixelSize: Style.font.subtitle
      font.bold: true
    }

    Rectangle {
      id: passwordBox
      visible: quickAccessRoot.view === QuickAccessModel.VIEW_LOCKED
      width: parent.width
      height: 34
      radius: Style.cornerRadius
      color: "transparent"
      border.width: 1
      border.color: passwordInput.activeFocus ? quickAccessRoot.accent : quickAccessRoot.borderColor
      opacity: quickAccessRoot.busy ? 0.6 : 1

      TextInput {
        id: passwordInput
        anchors.fill: parent
        anchors.leftMargin: 10
        anchors.rightMargin: 10
        verticalAlignment: TextInput.AlignVCenter
        clip: true
        echoMode: TextInput.Password
        readOnly: quickAccessRoot.busy
        color: quickAccessRoot.foreground
        selectionColor: quickAccessRoot.accent
        font.family: quickAccessRoot.fontFamily
        font.pixelSize: Style.font.body
        Keys.onReturnPressed: quickAccessRoot.submitUnlock()
        Keys.onEnterPressed: quickAccessRoot.submitUnlock()
        Keys.onEscapePressed: quickAccessRoot.closeRequested()

        Text {
          textFormat: Text.PlainText
          anchors.fill: parent
          verticalAlignment: Text.AlignVCenter
          visible: passwordInput.text === ""
          text: quickAccessRoot.busy
            ? quickAccessRoot.strings.t("quickAccess.unlocking", "Unlocking…")
            : quickAccessRoot.strings.t("quickAccess.passwordPlaceholder", "Master password, then Enter")
          color: quickAccessRoot.muted
          font: passwordInput.font
        }
      }
    }

    // --- messages ----------------------------------------------------------
    Text {
      id: messageText
      textFormat: Text.PlainText
      visible: text !== ""
      width: parent.width
      wrapMode: Text.Wrap
      text: {
        var v = quickAccessRoot.view
        if (v === QuickAccessModel.VIEW_LOADING) return quickAccessRoot.strings.t("quickAccess.loading", "Loading vault…")
        if (v === QuickAccessModel.VIEW_SIGNED_OUT) return quickAccessRoot.strings.t("quickAccess.signedOut", "You are not signed in. Open Bitwarden to sign in.")
        if (v === QuickAccessModel.VIEW_ENGINE_UNAVAILABLE) return quickAccessRoot.strings.t("quickAccess.engineUnavailable", "The omawarden engine did not answer. Open Bitwarden for details.")
        if (quickAccessRoot.showingList && quickAccessRoot.rankedItems.length === 0) {
          return quickAccessRoot.query === ""
            ? quickAccessRoot.strings.t("quickAccess.noLogins", "No logins in the vault.")
            : quickAccessRoot.strings.t("quickAccess.noMatches", "No logins match.")
        }
        return ""
      }
      color: quickAccessRoot.muted
      font.family: quickAccessRoot.fontFamily
      font.pixelSize: Style.font.body
    }

    Text {
      id: confirmationMessage
      objectName: "confirmationMessage"
      textFormat: Text.PlainText
      visible: quickAccessRoot.showingDetails && quickAccessRoot.confirmationText !== "" && quickAccessRoot.errorText === ""
      width: parent.width
      wrapMode: Text.Wrap
      text: quickAccessRoot.confirmationText
      color: quickAccessRoot.accent
      font.family: quickAccessRoot.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    Text {
      id: errorMessage
      textFormat: Text.PlainText
      visible: quickAccessRoot.errorText !== ""
      width: parent.width
      wrapMode: Text.Wrap
      text: quickAccessRoot.errorText
      color: quickAccessRoot.urgent
      font.family: quickAccessRoot.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    // --- footer ------------------------------------------------------------
    Rectangle {
      width: parent.width
      height: 1
      color: quickAccessRoot.borderColor
    }

    Item {
      width: parent.width
      height: 22

      Text {
        textFormat: Text.PlainText
        anchors.left: parent.left
        anchors.right: footerActions.left
        anchors.rightMargin: 8
        anchors.verticalCenter: parent.verticalCenter
        elide: Text.ElideRight
        visible: quickAccessRoot.view === QuickAccessModel.VIEW_UNLOCKED
        text: quickAccessRoot.showingDetails
          ? quickAccessRoot.strings.t("quickAccess.detailHint", "↵ password · ⇧↵ password, then code · Esc back")
          : quickAccessRoot.strings.t("quickAccess.shortcutHint", "↵ details · ⇧↵ password, then code · Ctrl+↵ code")
        color: quickAccessRoot.muted
        font.family: quickAccessRoot.fontFamily
        font.pixelSize: Style.font.caption
      }

      Row {
        id: footerActions
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: 4

        GhostIconButton {
          objectName: "retryButton"
          visible: quickAccessRoot.view === QuickAccessModel.VIEW_ENGINE_UNAVAILABLE
          iconText: ""
          fontFamily: quickAccessRoot.fontFamily
          foreground: quickAccessRoot.foreground
          muted: quickAccessRoot.muted
          onClicked: quickAccessRoot.retryRequested()
        }
        GhostIconButton {
          objectName: "lockButton"
          visible: quickAccessRoot.view === QuickAccessModel.VIEW_UNLOCKED
          iconText: ""
          fontFamily: quickAccessRoot.fontFamily
          foreground: quickAccessRoot.foreground
          muted: quickAccessRoot.muted
          onClicked: quickAccessRoot.lockRequested()
        }
        GhostIconButton {
          objectName: "openOverlayButton"
          iconText: ""
          fontFamily: quickAccessRoot.fontFamily
          foreground: quickAccessRoot.foreground
          muted: quickAccessRoot.muted
          onClicked: quickAccessRoot.openOverlayRequested()
        }
      }
    }
  }
}
