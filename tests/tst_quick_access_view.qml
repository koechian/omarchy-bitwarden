import QtQuick
import "lib"
import "../components" as Components
import "../components/QuickAccessModel.js" as QuickAccessModel

// The bar dropdown's view: Enter and a click open the details page, quick
// copies from the list ask to close the dropdown while copies from the
// details page keep it open, the paste sequence is offered only for items
// with a password and a code, the master password leaves the field when
// submitted and when the dropdown closes, and markup in item names is shown
// as plain text.
Item {
  id: testRunner
  width: 400
  height: 600

  property var copies: []
  property var sequences: []
  property var unlocks: []
  property int locks: 0
  property int overlayOpenings: 0
  property int closings: 0

  Components.QuickAccessView {
    id: quickAccess
    width: 380
    view: QuickAccessModel.VIEW_UNLOCKED
    vaultItems: [
      { id: "1", name: "Zeta <img src=\"https://example.invalid/x\">", type_name: "login", favorite: false,
        login: { username: "octocat", has_password: true, has_totp: true, uris: [{ uri: "https://teleport.example" }] } },
      { id: "2", name: "Amazon", type_name: "login", favorite: false,
        login: { username: "shopper", has_password: true, has_totp: false } }
    ]
    onCopyRequested: function(item, kind, closeAfter) {
      testRunner.copies = testRunner.copies.concat([item.id + ":" + kind + ":" + (closeAfter ? "close" : "stay")])
    }
    onSequenceRequested: function(item) { testRunner.sequences = testRunner.sequences.concat([item.id]) }
    onUnlockRequested: function(password) { testRunner.unlocks = testRunner.unlocks.concat([password]) }
    onLockRequested: testRunner.locks++
    onOpenOverlayRequested: testRunner.overlayOpenings++
    onCloseRequested: testRunner.closings++
  }

  function key(code, modifiers) {
    return { key: code, modifiers: modifiers || Qt.NoModifier }
  }

  function findByText(item, text) {
    if (item && item.text === text && item.textFormat !== undefined) return item
    var children = item ? item.children : []
    for (var i = 0; i < children.length; i++) {
      var found = findByText(children[i], text)
      if (found) return found
    }
    if (item && item.contentItem && item.contentItem !== item) return findByText(item.contentItem, text)
    return null
  }

  function findByObjectName(item, name) {
    if (item && item.objectName === name) return item
    var children = item ? item.children : []
    for (var i = 0; i < children.length; i++) {
      var found = findByObjectName(children[i], name)
      if (found) return found
    }
    return null
  }

  function findPasswordInput(item) {
    if (item && item.echoMode === TextInput.Password) return item
    var children = item ? item.children : []
    for (var i = 0; i < children.length; i++) {
      var found = findPasswordInput(children[i])
      if (found) return found
    }
    return null
  }

  function lastCopy() {
    return copies.length ? copies[copies.length - 1] : ""
  }

  Component.onCompleted: {
    console.log("Running quick access view tests...")

    // 1. Ranking and selection: "Amazon" sorts before "Zeta".
    Assert.check(quickAccess.rankedItems.length === 2 && quickAccess.selectedItem.id === "2", "the first ranked item is selected")

    // 2. List shortcuts.
    quickAccess.handleSearchKey(key(Qt.Key_Down))
    Assert.check(quickAccess.selectedItem.id === "1", "Down selects the next item")
    quickAccess.handleSearchKey(key(Qt.Key_Down))
    Assert.check(quickAccess.selectedItem.id === "1", "Down stops at the last item")
    quickAccess.handleSearchKey(key(Qt.Key_Return, Qt.ControlModifier))
    Assert.check(lastCopy() === "1:totp:close", "Ctrl+Enter in the list copies the code and closes")
    quickAccess.handleSearchKey(key(Qt.Key_U, Qt.ControlModifier))
    Assert.check(lastCopy() === "1:username:close", "Ctrl+U in the list copies the username and closes")
    quickAccess.handleSearchKey(key(Qt.Key_Return, Qt.ShiftModifier))
    Assert.check(sequences.length === 1 && sequences[0] === "1", "Shift+Enter in the list stages the paste sequence")
    quickAccess.handleSearchKey(key(Qt.Key_Up))
    var before = copies.length
    quickAccess.handleSearchKey(key(Qt.Key_Return, Qt.ControlModifier))
    Assert.check(copies.length === before, "Ctrl+Enter does nothing for an item without TOTP")
    quickAccess.handleSearchKey(key(Qt.Key_Return, Qt.ShiftModifier))
    Assert.check(sequences.length === 1, "no paste sequence for an item without TOTP")
    quickAccess.handleSearchKey(key(Qt.Key_L, Qt.ControlModifier))
    Assert.check(locks === 1, "Ctrl+L locks the vault")
    quickAccess.handleSearchKey(key(Qt.Key_O, Qt.ControlModifier))
    Assert.check(overlayOpenings === 1, "Ctrl+O opens the full window")

    // 3. Enter opens the details page; nothing is copied.
    quickAccess.handleSearchKey(key(Qt.Key_Down))
    before = copies.length
    quickAccess.handleSearchKey(key(Qt.Key_Return))
    Assert.check(quickAccess.showingDetails && quickAccess.detailItem.id === "1", "Enter opens the details page of the selected item")
    Assert.check(copies.length === before, "opening the details page copies nothing")

    // 4. Details page shortcuts keep the dropdown open.
    quickAccess.handleDetailKey(key(Qt.Key_Return))
    Assert.check(lastCopy() === "1:password:stay", "Enter on the details page copies the password and stays open")
    quickAccess.handleDetailKey(key(Qt.Key_Return, Qt.ControlModifier))
    Assert.check(lastCopy() === "1:totp:stay", "Ctrl+Enter on the details page copies the code and stays open")
    quickAccess.handleDetailKey(key(Qt.Key_U, Qt.ControlModifier))
    Assert.check(lastCopy() === "1:username:stay", "Ctrl+U on the details page copies the username and stays open")
    quickAccess.handleDetailKey(key(Qt.Key_Return, Qt.ShiftModifier))
    Assert.check(sequences.length === 2, "Shift+Enter on the details page stages the paste sequence")
    quickAccess.handleDetailKey(key(Qt.Key_Escape))
    Assert.check(quickAccess.showingList && closings === 0, "Escape on the details page returns to the list without closing")

    // 5. A refreshed listing without the item closes the details page.
    quickAccess.openDetails(quickAccess.rankedItems[1])
    var items = quickAccess.vaultItems
    quickAccess.vaultItems = [items[1]]
    Assert.check(quickAccess.showingList, "the details page closes when its item leaves the vault")
    quickAccess.vaultItems = items

    // 6. Busy: nothing is requested while a command runs.
    quickAccess.busy = true
    before = copies.length
    quickAccess.openDetails(quickAccess.rankedItems[1])
    quickAccess.handleDetailKey(key(Qt.Key_Return))
    quickAccess.handleDetailKey(key(Qt.Key_Return, Qt.ShiftModifier))
    Assert.check(copies.length === before && sequences.length === 2, "no copy or sequence is requested while busy")
    quickAccess.busy = false

    // 7. Locking leaves the details page.
    quickAccess.view = QuickAccessModel.VIEW_LOCKED
    Assert.check(quickAccess.detailItem === null, "a locked vault closes the details page")

    // 8. Unlock: the password is handed over once and leaves the field.
    var passwordField = findPasswordInput(quickAccess)
    Assert.check(passwordField !== null && passwordField.echoMode === TextInput.Password, "the locked view shows a masked password field")
    passwordField.text = "correct horse"
    quickAccess.submitUnlock()
    Assert.check(unlocks.length === 1 && unlocks[0] === "correct horse", "the password is handed to unlockRequested")
    Assert.check(passwordField.text === "", "the field is cleared on submit")
    quickAccess.submitUnlock()
    Assert.check(unlocks.length === 1, "an empty field does not unlock")
    passwordField.text = "typed but not sent"
    quickAccess.query = "kept while the card fades"
    quickAccess.clearSecretInput()
    Assert.check(passwordField.text === "", "starting to close clears a typed password at once")
    Assert.check(quickAccess.query === "kept while the card fades", "starting to close keeps what the fading card shows")
    passwordField.text = "typed but not sent"
    quickAccess.reset()
    Assert.check(passwordField.text === "", "the reset after the fade also clears a typed password")

    // 9. Query filters the list.
    quickAccess.view = QuickAccessModel.VIEW_UNLOCKED
    quickAccess.query = "amaz"
    Assert.check(quickAccess.rankedItems.length === 1 && quickAccess.selectedItem.id === "2", "the query filters and the selection resets")
    quickAccess.query = "zzz"
    Assert.check(quickAccess.selectedItem === null, "no selection when nothing matches")
    quickAccess.handleSearchKey(key(Qt.Key_Return))
    Assert.check(quickAccess.showingList, "Enter does nothing when nothing matches")
    quickAccess.reset()
    Assert.check(quickAccess.query === "", "reset clears the query")

    // 10. Sequence button visibility on the details page.
    quickAccess.openDetails(quickAccess.vaultItems[0])
    var sequenceButton = findByObjectName(quickAccess, "sequenceButton")
    Assert.check(sequenceButton !== null && sequenceButton.visible, "the paste sequence is offered for an item with a password and a code")
    quickAccess.openDetails(quickAccess.vaultItems[1])
    Assert.check(!sequenceButton.visible, "the paste sequence is not offered without a code")
    quickAccess.closeDetails()
    quickAccess.reset()
    Assert.check(quickAccess.listOpacity === 1 && quickAccess.listOffset === 0
      && quickAccess.detailOpacity === 1 && quickAccess.detailOffset === 0, "reset stops a page change and leaves both pages at rest")

    // List rows are built when the view is laid out, after this handler.
    layoutWait.start()
  }

  Timer {
    id: layoutWait
    interval: 200
    onTriggered: {
      // 11. Markup in a name is shown as plain text.
      var nameText = testRunner.findByText(quickAccess, "Zeta <img src=\"https://example.invalid/x\">")
      Assert.check(nameText !== null && nameText.textFormat === Text.PlainText, "item names are plain text")

      // 12. Section labels while recent logins lead the list.
      quickAccess.vaultItems = [
        { id: "r", name: "Teleport", type_name: "login", favorite: false, usage_score: 4,
          login: { username: "me", has_password: true, has_totp: true } },
        { id: "o", name: "Amazon", type_name: "login", favorite: false, usage_score: 0,
          login: { username: "shopper", has_password: true } }
      ]
      Assert.check(quickAccess.recentCount === 1, "one recent login")
      Assert.check(quickAccess.sectionTitleAt(0) === "Recent" && quickAccess.sectionTitleAt(1) === "All logins", "section labels head the recent and the other logins")
      Assert.check(quickAccess.listHeight() === 2 * quickAccess.rowHeight + 2 * quickAccess.sectionHeaderHeight, "the list makes room for both labels")
      quickAccess.query = "tele"
      Assert.check(quickAccess.recentCount === 0 && quickAccess.sectionTitleAt(0) === "", "no section labels while a query is typed")
      quickAccess.reset()
      Qt.exit(Assert.exitCode())
    }
  }
}
