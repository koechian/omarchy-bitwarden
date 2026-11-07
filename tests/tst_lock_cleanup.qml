import QtQuick
import QtQuick.Controls
import "lib"
import "../components" as Components
import "../components/SecretFieldCatalog.js" as SecretFieldCatalog

// Lock cleanup against redacted items: locking drops the vault state, closes
// every modal and drops every revealed value held by the release controller
// (bound the way OmarchyBitwarden.qml binds it), and replies that arrive
// after the lock repopulate nothing.
Item {
  id: testRunner
  width: 400
  height: 300

  // State under test reproducing OmarchyBitwarden properties
  property var authState: ({
    status: "unlocked",
    server_url: "https://vault.example.com",
    user_email: "test@example.com",
    has_session: true
  })
  property bool opened: true

  property var rawVaultItems: []
  property var filteredItems: []
  property string lastVaultItemsRawText: ""
  property real lastSyncTime: 0
  property string searchQuery: ""
  property string activeCategory: "all"
  property string activeVaultScope: "all"
  property string activeFolderScope: "all"
  property int selectedIndex: 0
  readonly property var selectedItem: (filteredItems.length > selectedIndex) ? filteredItems[selectedIndex] : null

  property bool showActionPalette: false
  property int actionPaletteIndex: 0
  property var currentAvailableActions: []

  property bool showPasswordHistoryModal: false
  property var activePasswordHistoryItem: null

  property bool showPasswordGeneratorModal: false

  property var commands: []

  readonly property var redactedLogin: ({
    id: "item-1", name: "Secret Item", type: 1, type_name: "login", has_notes: true,
    login: { username: "octocat", uris: [], has_password: true, has_totp: true, has_password_history: true, password_history_count: 1 }
  })

  Components.SecretReleaseController {
    id: secretRelease
    helperPath: "omawarden"
    active: testRunner.opened && Boolean(testRunner.authState && testRunner.authState.status === "unlocked")
    itemId: testRunner.selectedItem ? String(testRunner.selectedItem.id || "") : ""
    totpCountdownIntervalMs: 50
    onCommandRequested: function(argv) { testRunner.commands = testRunner.commands.concat([argv]) }
  }

  function reply(payload) {
    secretRelease.handleCommandOutput(JSON.stringify(payload))
    secretRelease.handleCommandExit(0)
  }

  function clearSensitiveState() {
    testRunner.rawVaultItems = []
    testRunner.filteredItems = []
    testRunner.lastVaultItemsRawText = ""
    testRunner.lastSyncTime = 0
    testRunner.searchQuery = ""
    testRunner.activeCategory = "all"
    testRunner.activeVaultScope = "all"
    testRunner.activeFolderScope = "all"
    testRunner.selectedIndex = 0

    secretRelease.reset()

    testRunner.showActionPalette = false
    testRunner.actionPaletteIndex = 0
    testRunner.currentAvailableActions = []

    testRunner.showPasswordHistoryModal = false
    testRunner.activePasswordHistoryItem = null

    testRunner.showPasswordGeneratorModal = false
  }

  function doLock() {
    testRunner.clearSensitiveState()
    testRunner.authState = ({
      status: "locked",
      server_url: (testRunner.authState && testRunner.authState.server_url) || "",
      user_email: (testRunner.authState && testRunner.authState.user_email) || "",
      has_session: Boolean(testRunner.authState && testRunner.authState.has_session)
    })
  }

  // Simulated asynchronous handler for vaultListProc
  function simulateVaultListFinished(rawJsonText) {
    if (!testRunner.authState || testRunner.authState.status !== "unlocked") {
      testRunner.clearSensitiveState()
      return
    }
    testRunner.rawVaultItems = JSON.parse(rawJsonText) || []
  }

  Component.onCompleted: {
    console.log("Running Frontend Lock Cleanup and Async Guard Tests...")

    // 1. Populate state with redacted items, revealed values, modals and actions
    rawVaultItems = [redactedLogin]
    filteredItems = rawVaultItems
    lastVaultItemsRawText = JSON.stringify(rawVaultItems)
    searchQuery = "secret"
    Assert.check(JSON.parse(lastVaultItemsRawText)[0].login.password === undefined, "Fixture is redacted: no password value in the listing")

    secretRelease.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    reply({ ok: true, id: "item-1", field: SecretFieldCatalog.LOGIN_PASSWORD, value: "SecretPassword123" })
    secretRelease.reveal(SecretFieldCatalog.LOGIN_TOTP)
    reply({ ok: true, id: "item-1", field: SecretFieldCatalog.LOGIN_TOTP, value: "123456", seconds_remaining: 25, period: 30 })
    secretRelease.reveal(SecretFieldCatalog.NOTES)

    showActionPalette = true
    actionPaletteIndex = 2
    currentAvailableActions = [{ label: "Copy Password", action: function() {} }]
    showPasswordHistoryModal = true
    activePasswordHistoryItem = redactedLogin
    showPasswordGeneratorModal = true

    Assert.check(rawVaultItems.length === 1, "Initial vault items populated")
    Assert.check(secretRelease.revealedValue(SecretFieldCatalog.LOGIN_PASSWORD) === "SecretPassword123", "Initial revealed password held by the controller")
    Assert.check(secretRelease.totpCode === "123456", "Initial revealed TOTP held by the controller")
    Assert.check(secretRelease.isPending(SecretFieldCatalog.NOTES), "Initial notes reveal in flight")
    Assert.check(currentAvailableActions.length === 1, "Initial action closures populated")

    // 2. Perform doLock()
    var commandsBeforeLock = commands.length
    doLock()

    // 3. Verify vault state, closures, modals and revealed values are wiped
    Assert.check(authState.status === "locked", "Auth state transitioned to locked")
    Assert.check(authState.has_session === true, "Session flag preserved for unlock view")
    Assert.check(rawVaultItems.length === 0, "rawVaultItems wiped on lock")
    Assert.check(filteredItems.length === 0, "filteredItems wiped on lock")
    Assert.check(lastVaultItemsRawText === "", "lastVaultItemsRawText wiped on lock")
    Assert.check(searchQuery === "", "searchQuery reset on lock")

    Assert.check(!secretRelease.active, "Release controller inactive once locked")
    Assert.check(Object.keys(secretRelease.revealedValues).length === 0, "Revealed values dropped on lock")
    Assert.check(Object.keys(secretRelease.requestedFields).length === 0, "Pending reveals dropped on lock")
    Assert.check(secretRelease.totpCode === "" && secretRelease.totpSecondsRemaining === 0, "Revealed TOTP and its countdown dropped on lock")

    Assert.check(showActionPalette === false, "Action palette closed on lock")
    Assert.check(actionPaletteIndex === 0, "Action palette index reset on lock")
    Assert.check(currentAvailableActions.length === 0, "Action closures wiped on lock")

    Assert.check(showPasswordHistoryModal === false, "Password history modal closed on lock")
    Assert.check(activePasswordHistoryItem === null, "activePasswordHistoryItem nulled on lock")

    Assert.check(showPasswordGeneratorModal === false, "Password generator modal closed on lock")

    // 4. Late asynchronous replies repopulate nothing.
    simulateVaultListFinished(JSON.stringify([{ id: "item-2", name: "Late Leaked Item" }]))
    Assert.check(rawVaultItems.length === 0, "Late vault list response rejected when locked")

    reply({ ok: true, id: "item-1", field: SecretFieldCatalog.NOTES, value: "late note" })
    Assert.check(Object.keys(secretRelease.revealedValues).length === 0, "Late reveal reply rejected when locked")

    secretRelease.reveal(SecretFieldCatalog.LOGIN_TOTP)
    Assert.check(commands.length === commandsBeforeLock, "A locked overlay releases nothing")

    if (Assert.failures === 0)
      console.log("All Lock Cleanup and Async Guard tests passed successfully!")
    Qt.exit(Assert.exitCode())
  }
}
