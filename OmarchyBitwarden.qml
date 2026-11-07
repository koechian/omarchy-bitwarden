import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "./components"
import "./components/SecretFieldCatalog.js" as SecretFieldCatalog
import "./components/UriPolicy.js" as UriPolicy
import "./components/VaultSearch.js" as VaultSearch

Item {
  id: root

  Component.onCompleted: {
    root.checkDependencies()
    root.resolveHelper()
  }

  property var shell: null
  property var manifest: null
  property bool opened: false
  onOpenedChanged: {
    if (root.opened) {
      root.checkDependencies()
      root.resolveHelper()
      root.refreshAuthStatus()
    }
  }
  function toLocalPath(url) {
    if (!url) return ""
    var str = url.toString ? url.toString() : String(url)
    return str.replace(/^file:\/+/i, "/")
  }

  property string helperPath: "omawarden"
  // The first engine that redacts items and releases secrets per field (ADR 0027).
  readonly property string minimumEngineVersion: "0.12.0"
  readonly property string minimumGeneratorEngineVersion: "0.9.0"
  readonly property bool isGeneratorEngineOutdated: {
    var ver = (root.cliHealth && root.cliHealth.version) ? root.cliHealth.version : ""
    if (!ver) return false
    return root.compareSemVer(ver, root.minimumGeneratorEngineVersion) < 0
  }

  function isEngineVersionSatisfied(ver) {
    if (!ver) return false
    var parsed = root.parseSemVer(ver)
    if (!parsed) return false
    var min = root.parseSemVer(root.minimumEngineVersion)
    if (!min) return false
    for (var i = 0; i < 3; i++) {
      if (parsed[i] > min[i]) return true
      if (parsed[i] < min[i]) return false
    }
    return true
  }

  function resolveHelper() {
    resolveHelperProc.running = false
    resolveHelperProc.command = ["sh", "-c", "command -v omawarden"]
    resolveHelperProc.running = true
  }

  Process {
    id: resolveHelperProc
    command: []
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var p = (text || "").trim()
        if (p.length > 0) {
          root.helperPath = p
        }
      }
    }
    onExited: function(code) {
      if (code !== 0) {
        root.helperPath = ""
        root.cliHealth = ({
          installed: false,
          ok: false,
          version: "",
          server_reachable: false,
          keyring_available: false,
          clipboard_available: false,
          error: "omawarden engine is missing or not installed."
        })
      } else {
        root.refreshConfig()
        root.refreshHealth()
        root.refreshAuthStatus()
      }
    }
  }

  // Dependency Checking State
  property bool dependenciesMissing: false
  property bool isCheckingDependencies: false
  property var missingDependencyPackages: []

  function checkDependencies() {
    if (dependencyCheckView) {
      dependencyCheckView.resetToChecking()
    }
    root.isCheckingDependencies = true
    pacmanCheckProc.running = false
    pacmanCheckProc.command = ["pacman", "-Q", "omawarden", "omawarden-bin", "omawarden-git", "libsecret", "wl-clipboard"]
    pacmanCheckProc.running = true
  }

  readonly property string engineSource: {
    if (!cliHealth || !cliHealth.installed) return ""
    if (dependencyCheckView) {
      for (var i = 0; i < dependencyCheckView.dependencyModel.count; i++) {
        var item = dependencyCheckView.dependencyModel.get(i)
        if (item.pkgName === "omawarden" && item.status === "installed") {
          return item.isLocalFallback ? "local" : "aur"
        }
      }
    }
    if (root.helperPath && root.helperPath !== "omawarden") {
      return "aur"
    }
    return ""
  }

  readonly property string enginePackage: {
    if (dependencyCheckView) {
      for (var i = 0; i < dependencyCheckView.dependencyModel.count; i++) {
        var item = dependencyCheckView.dependencyModel.get(i)
        if (item.pkgName === "omawarden") {
          if (item.status === "installed" && item.installedPackage) {
            return item.installedPackage
          }
        }
      }
    }
    return ""
  }

  function finalizeDependencyCheck() {
    root.isCheckingDependencies = false
    if (dependencyCheckView) {
      var missing = dependencyCheckView.finalizeCheck()
      root.missingDependencyPackages = missing
      root.dependenciesMissing = (missing.length > 0)
      if (root.dependenciesMissing) {
        if (missing.indexOf("omawarden") !== -1) {
          root.helperPath = ""
          root.cliHealth = ({
            installed: false,
            ok: false,
            version: "",
            server_reachable: false,
            keyring_available: false,
            clipboard_available: false,
            error: "omawarden engine is missing or not installed."
          })
        }
      } else {
        root.resolveHelper()
      }
    }
  }

  Process {
    id: pacmanCheckProc
    running: false

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (dependencyCheckView) {
          dependencyCheckView.parsePacmanStdout(text)
        }
      }
    }

    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (dependencyCheckView) {
          dependencyCheckView.parsePacmanStderr(text)
        }
      }
    }

    onExited: function(code) {
      root.completePackageCheck()
    }
  }

  // pacman knows only packaged engines. This fork's engine is built from
  // source, so when no package satisfies the check, look for a local build
  // on PATH before reporting the engine as missing.
  function completePackageCheck() {
    if (dependencyCheckView && dependencyCheckView.engineNeedsLocalProbe()) {
      localEngineProbeProc.running = false
      localEngineProbeProc.running = true
      return
    }
    root.finalizeDependencyCheck()
  }

  Process {
    id: localEngineProbeProc
    command: ["sh", "-c", "engine=$(command -v omawarden) && \"$engine\" --version"]
    running: false

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (dependencyCheckView) {
          dependencyCheckView.applyLocalEngineProbe(text)
        }
      }
    }

    onExited: function(code) {
      root.finalizeDependencyCheck()
    }
  }

  // Configuration & Engine Health State
  property var config: ({
    server_url: "https://vault.bitwarden.com",
    auto_lock_minutes: 15,
    clipboard_clear_seconds: 30,
    email: ""
  })
  property bool rememberEmailChecked: true
  property int configSeq: 0
  property bool show2FAField: false
  property bool isNewDeviceVerification: false
  property int twoFactorProvider: 0
  property var availableTwoFactorProviders: []
  property string fido2Status: ""

  property var cliHealth: ({
    installed: false,
    ok: false,
    version: "",
    server_reachable: false,
    keyring_available: false,
    clipboard_available: false,
    error: "Checking CLI status..."
  })
  property bool engineAttestationVerified: false

  property var authState: ({
    status: "unauthenticated",
    server_url: "",
    user_email: "",
    has_session: false
  })

  // Vault Items & Search State
  property var rawVaultItems: []
  property var filteredItems: []
  property string searchQuery: ""
  property var categoryList: ["all", "login", "card", "identity", "note"]
  property string activeCategory: "all"
  property string activeVaultScope: "all"
  property string activeFolderScope: "all"
  property int selectedIndex: 0

  // Details Inspector State. Revealed secrets live only in secretRelease.
  property bool showActionPalette: false
  property int actionPaletteIndex: 0
  property var currentAvailableActions: []
  property bool showPasswordHistoryModal: false
  property var activePasswordHistoryItem: null
  property bool showPasswordGeneratorModal: false
  property string passwordGeneratorModalMode: "password"
  readonly property bool hasActiveModal: root.showActionPalette || root.showPasswordHistoryModal || root.showPasswordGeneratorModal

  property string currentView: "auto"
  property string loginMethod: "password"
  property string statusMessage: ""
  property string errorMessage: ""
  property bool isBusy: false
  property bool isLoadingVault: false
  property bool lastSyncWasManual: false
  property real lastSyncTime: 0
  property int syncCooldownSeconds: 300
  property string lastVaultItemsRawText: ""
  property var logBuffer: []

  readonly property color background: Commons.Color.menu.background
  readonly property color foreground: Commons.Color.menu.text
  readonly property color borderColor: Commons.Color.menu.border
  readonly property color accent: Commons.Color.menu.selectedText
  readonly property color selectedBackground: Commons.Color.menu.selectedBackground
  readonly property color muted: Commons.Color.muted
  readonly property string fontFamily: Style.font.menuFamily
  readonly property int defaultClipboardClearSeconds: 30
  readonly property QtObject strings: Commons.Translations {
    directory: Qt.resolvedUrl("i18n")
  }

  readonly property var selectedItem: {
    if (filteredItems && filteredItems.length > 0 && selectedIndex >= 0 && selectedIndex < filteredItems.length) {
      return filteredItems[selectedIndex]
    }
    return null
  }

  readonly property string effectiveView: {
    if (dependenciesMissing && currentView !== "settings") return "dependency_check"
    if (currentView !== "auto") return currentView
    if (authState.status === "unlocked" && Boolean(authState.has_session)) return "search"
    if (authState.status === "locked" && Boolean(authState.has_session)) return "unlock"
    return "login"
  }

  onCurrentViewChanged: {
    if (root.currentView === "settings" || root.effectiveView === "settings") {
      root.refreshHealth()
      root.refreshConfig()
    }
  }

  onEffectiveViewChanged: {
    Qt.callLater(function() {
      if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.hasActiveModal) {
        searchHeader.searchField.forceActiveFocus()
      } else if (root.opened && root.effectiveView !== "dependency_check" && authViewComponent && authViewComponent.unlockInput) {
        authViewComponent.unlockInput.forceActiveFocus()
      }
    })
  }

  function clearSensitiveState() {
    root.rawVaultItems = []
    root.filteredItems = []
    root.lastVaultItemsRawText = ""
    root.lastSyncTime = 0
    root.searchQuery = ""
    root.activeCategory = "all"
    root.activeVaultScope = "all"
    root.activeFolderScope = "all"
    root.selectedIndex = 0

    secretRelease.reset()

    root.showActionPalette = false
    root.actionPaletteIndex = 0
    root.currentAvailableActions = []

    root.showPasswordHistoryModal = false
    root.activePasswordHistoryItem = null

    root.showPasswordGeneratorModal = false
    if (passwordGeneratorModalComponent) {
      passwordGeneratorModalComponent.generatedPassword = ""
      passwordGeneratorModalComponent.errorMessage = ""
    }
    if (passwordGenProc.running) {
      passwordGenProc.isCanceled = true
      passwordGenProc.running = false
    }

    root.twoFactorProvider = 0
    root.availableTwoFactorProviders = []

    if (authViewComponent && typeof authViewComponent.clearInputs === "function") {
      authViewComponent.clearInputs()
    }
  }

  // Whether the last search survives closing and reopening the overlay.
  function canRememberSearch() {
    return Boolean(root.config && root.config.remember_last_search === true && root.authState && root.authState.status === "unlocked")
  }

  // Keeps a remembered selection inside the current result list.
  function clampSelectedIndex() {
    var count = root.filteredItems ? root.filteredItems.length : 0
    root.selectedIndex = count > 0 ? Math.min(Math.max(root.selectedIndex, 0), count - 1) : 0
  }

  // Closes every modal and drops revealed values and palette closures.
  function resetTransientState() {
    root.showActionPalette = false
    root.showPasswordHistoryModal = false
    root.showPasswordGeneratorModal = false
    root.activePasswordHistoryItem = null
    root.currentAvailableActions = []
    secretRelease.reset()
  }

  function focusActiveView(cursorAtEnd) {
    if (root.effectiveView === "search" && searchHeader) {
      searchHeader.focusSearch(cursorAtEnd)
    } else if (root.effectiveView !== "dependency_check" && authViewComponent && authViewComponent.unlockInput) {
      authViewComponent.unlockInput.forceActiveFocus()
    }
  }

  // payloadJson is part of the shell's plugin interface; no view payload is used.
  function open(payloadJson) {
    root.opened = true
    root.errorMessage = ""
    root.statusMessage = ""
    root.currentView = "auto"
    var canRemember = root.canRememberSearch()
    if (canRemember) {
      root.clampSelectedIndex()
    } else {
      root.searchQuery = ""
      root.selectedIndex = 0
    }
    if (!root.authState || root.authState.status !== "unlocked") {
      root.clearSensitiveState()
    } else {
      root.resetTransientState()
    }
    root.checkDependencies()
    if (!root.dependenciesMissing) {
      root.refreshHealth()
      root.refreshConfig()
      root.refreshAuthStatus()
    }
    if (root.effectiveView === "search" && root.selectedItem) {
      root.handleSelectedItemChanged()
    }
    Qt.callLater(function() { root.focusActiveView(canRemember) })
  }

  function close() {
    root.opened = false
    root.resetTransientState()
    if (!root.canRememberSearch()) {
      root.searchQuery = ""
      root.selectedIndex = 0
    }
  }

  function dismiss() {
    root.close()
    if (root.shell && typeof root.shell.hide === "function") {
      root.shell.hide((root.manifest && root.manifest.id) || "icyleaf.bitwarden")
    }
  }

  function toggle() {
    if (root.opened) root.dismiss()
    else root.open("{}")
  }

  function refreshConfig() {
    if (configGetProc.running) return
    root.configSeq++
    configGetProc.seq = root.configSeq
    configGetProc.command = [root.helperPath, "config", "get"]
    configGetProc.running = true
  }


  function parseSemVer(v) {
    if (!v || typeof v !== "string") return null
    var clean = String(v).replace(/^omawarden[\s-]+|^v/i, "").trim()
    var match = clean.match(/^(\d+)\.(\d+)(?:\.(\d+))?/)
    if (!match) return null
    var major = parseInt(match[1], 10)
    var minor = parseInt(match[2], 10)
    var patch = (match[3] !== undefined && match[3] !== "") ? parseInt(match[3], 10) : 0
    return [major, minor, patch]
  }

  function compareSemVer(v1, v2) {
    var a = parseSemVer(v1)
    var b = parseSemVer(v2)
    if (!a && !b) return 0
    if (!a) return -1
    if (!b) return 1
    for (var i = 0; i < 3; i++) {
      if (a[i] > b[i]) return 1
      if (a[i] < b[i]) return -1
    }
    return 0
  }

  function refreshHealth() {
    if (healthProc.running) return
    healthProc.command = [
      "sh", "-c",
      "if command -v \"$1\" >/dev/null 2>&1 || [ -x \"$1\" ]; then exec \"$1\" health; else exit 127; fi",
      "--",
      root.helperPath
    ]
    healthProc.running = true
  }

  // ADR-0025: the engine advertises quick-unlock readiness on its ping when
  // enabled in settings and a key is retained by a soft lock.
  property bool quickUnlockReady: false

  function refreshQuickUnlockAvailability() {
    if (!root.helperPath) {
      root.quickUnlockReady = false
      return
    }
    if (quickUnlockCheckProc.running) return
    quickUnlockCheckProc.command = [root.helperPath, "auth", "quick-unlock-check"]
    quickUnlockCheckProc.running = true
  }

  function refreshAuthStatus() {
    if (authStatusProc.running) return
    authStatusProc.command = [
      "sh", "-c",
      "if command -v \"$1\" >/dev/null 2>&1 || [ -x \"$1\" ]; then exec \"$1\" auth status; else exit 127; fi",
      "--",
      root.helperPath
    ]
    authStatusProc.running = true
    // Readiness only matters on the locked view. The lockSyncTimer polls auth
    // status every 3s while the vault is unlocked, and a second helper spawn
    // per tick would be pure noise; the transition back to locked refreshes
    // readiness from the auth-status handler instead.
    if (!root.authState || root.authState.status !== "unlocked") {
      root.refreshQuickUnlockAvailability()
    }
  }

  function syncVault(isBackground, force) {
    var hasSession = root.authState && Boolean(root.authState.has_session)
    if (!hasSession) {
      root.logWarn("omarchy:vault", "Cannot sync vault: not logged in.")
      return
    }
    if (vaultSyncProc.running) return
    var now = Date.now()
    if (isBackground && !force) {
      if (root.lastSyncTime > 0 && (now - root.lastSyncTime) < (root.syncCooldownSeconds * 1000)) {
        return
      }
    }
    root.logInfo("omarchy:vault", "Starting vault sync (manual: " + (!isBackground) + ", force: " + Boolean(force) + ")...")
    root.lastSyncWasManual = !isBackground
    root.isBusy = true
    root.statusMessage = "Syncing vault with Bitwarden..."
    vaultSyncProc.command = [root.helperPath, "vault", "sync"]
    vaultSyncProc.running = true
  }

  function formatSyncError(err) {
    if (!err) return "Vault sync failed."
    var str = String(err).trim()

    var isTokenRefresh = str.toLowerCase().indexOf("token refresh") !== -1 || str.toLowerCase().indexOf("refresh token") !== -1
    var isApiAuth = str.toLowerCase().indexOf("api auth") !== -1 || str.toLowerCase().indexOf("api key") !== -1

    var httpMatch = str.match(/HTTP\s+(\d{3}(?:\s+[A-Za-z]+){0,4})/i)
    if (httpMatch && httpMatch[1]) {
      var httpCode = "HTTP " + httpMatch[1].trim()
      if (isTokenRefresh) {
        return "Token refresh failed: " + httpCode
      } else if (isApiAuth) {
        return "API auth failed: " + httpCode
      } else {
        return "Vault sync failed: " + httpCode
      }
    }

    if (str.toLowerCase().indexOf("connection refused") !== -1) {
      return (isTokenRefresh ? "Token refresh failed: " : "Vault sync failed: ") + "Connection refused"
    }
    if (str.toLowerCase().indexOf("timed out") !== -1 || str.toLowerCase().indexOf("timeout") !== -1) {
      return (isTokenRefresh ? "Token refresh failed: " : "Vault sync failed: ") + "Request timed out"
    }

    return str
  }

  function scopeExists(scopes, scopeId) {
    return scopes.some(function(scope) { return scope.id === scopeId })
  }

  // Falls back to "all" for a vault or folder scope the new listing lacks.
  function resetUnknownScopes() {
    var fixedVaultScopes = ["all", "personal"]
    var fixedFolderScopes = ["all", "none"]
    if (fixedVaultScopes.indexOf(root.activeVaultScope) === -1 && !root.scopeExists(root.getAvailableVaultScopes(), root.activeVaultScope)) {
      root.activeVaultScope = "all"
    }
    if (fixedFolderScopes.indexOf(root.activeFolderScope) === -1 && !root.scopeExists(root.getAvailableFolderScopes(), root.activeFolderScope)) {
      root.activeFolderScope = "all"
    }
  }

  // `vault list` prints an array of redacted items; a locked daemon answers
  // with an error envelope instead, which is not a listing. A listing in
  // which any item carries a secret value comes from an engine that does not
  // redact (contracts.md 3.2): it is discarded whole, never stored, and the
  // user is told to install the hardened engine.
  function applyVaultListing(listing, rawText) {
    var handlers = {}
    handlers[SecretFieldCatalog.LISTING_REDACTED] = root.storeVaultListing
    handlers[SecretFieldCatalog.LISTING_UNREDACTED] = root.rejectUnredactedListing
    handlers[SecretFieldCatalog.LISTING_NOT_A_LISTING] = root.rejectVaultReply
    handlers[SecretFieldCatalog.classifyVaultListing(listing)](listing, rawText)
  }

  function storeVaultListing(listing, rawText) {
    root.lastVaultItemsRawText = rawText
    root.rawVaultItems = listing
    root.resetUnknownScopes()
  }

  function discardVaultListing() {
    root.lastVaultItemsRawText = ""
    root.rawVaultItems = []
    root.filteredItems = []
  }

  function rejectUnredactedListing() {
    root.discardVaultListing()
    root.errorMessage = root.strings.t("error.engine_not_redacting", "The installed omawarden engine sent secrets with the vault list, so the list was discarded. Install the hardened omawarden %1 or later and unlock again.").arg(root.minimumEngineVersion)
    root.logError("omarchy:vault", "Discarded a vault listing that carried secret values: the engine does not redact items (requires omawarden >= " + root.minimumEngineVersion + ")")
  }

  function rejectVaultReply(listing) {
    root.discardVaultListing()
    if (listing && SecretFieldCatalog.errorLocksVault(listing.error_code)) root.markVaultLocked()
  }

  function loadVaultItems() {
    root.logInfo("omarchy:vault", "Loading vault items from local daemon/engine...")
    root.isLoadingVault = true
    vaultListProc.command = [root.helperPath, "vault", "list"]
    vaultListProc.running = true
  }

  function sanitizeServerUrl(url) {
    if (!url || !url.trim()) return "Default (https://vault.bitwarden.com)"
    var trimmed = url.trim()
    var lower = trimmed.toLowerCase()
    if (lower === "https://vault.bitwarden.com" || lower === "http://vault.bitwarden.com" ||
        lower === "https://api.bitwarden.com" || lower === "https://identity.bitwarden.com" ||
        lower === "https://bitwarden.com") {
      return "Official Cloud (" + trimmed + ")"
    }
    if (lower === "https://vault.bitwarden.eu" || lower === "http://vault.bitwarden.eu" ||
        lower === "https://api.bitwarden.eu" || lower === "https://identity.bitwarden.eu" ||
        lower === "https://bitwarden.eu") {
      return "Official Cloud (" + trimmed + ")"
    }
    var scheme = (lower.indexOf("http://") === 0) ? "http" : "https"
    if (lower.indexOf("127.0.0.1") !== -1 || lower.indexOf("localhost") !== -1 || lower.indexOf("192.168.") !== -1 || lower.indexOf("10.") !== -1 || lower.indexOf("172.") !== -1) {
      return "Self-Hosted / Local IP (" + scheme + "://<REDACTED_LOCAL_IP>)"
    }
    return "Self-Hosted / Custom (" + scheme + "://<REDACTED_CUSTOM_HOST>)"
  }

  function sanitizeLog(text) {
    if (!text) return ""
    var str = String(text)
    str = str.replace(/bearer\s+[a-z0-9_\-\.]+/gi, "Bearer <REDACTED>")
    str = str.replace(/("password"|"masterPasswordHash"|"master_password_hash")\s*:\s*"[^"]*"/gi, '$1:"<REDACTED>"')
    str = str.replace(/("client_secret"|"clientSecret"|"userKey"|"privateKey")\s*:\s*"[^"]*"/gi, '$1:"<REDACTED>"')
    str = str.replace(/("code"|"twoFactorToken"|"newDeviceOtp"|"new_device_otp")\s*:\s*"[^"]*"/gi, '$1:"<REDACTED>"')
    return str
  }

  function appendLog(level, source, message) {
    var sanitized = root.sanitizeLog(message)
    if (!sanitized || sanitized.trim().length === 0) return
    var ts = new Date().toISOString()
    var entry = {
      timestamp: ts,
      level: level.toUpperCase(),
      source: source || "omarchy:ui",
      message: sanitized.trim()
    }

    var buf = root.logBuffer.slice()
    buf.push(entry)
    if (buf.length > 500) {
      buf.shift()
    }
    root.logBuffer = buf

    var formatted = "[" + ts + "] [" + entry.level + "] [" + entry.source + "] " + entry.message
    if (entry.level === "ERROR") {
      console.error(formatted)
    } else if (entry.level === "WARN") {
      console.warn(formatted)
    } else {
      console.log(formatted)
    }
  }

  function logError(source, msg) { root.appendLog("ERROR", source, msg) }
  function logWarn(source, msg) { root.appendLog("WARN", source, msg) }
  function logInfo(source, msg) { root.appendLog("INFO", source, msg) }
  function logDebug(source, msg) { root.appendLog("DEBUG", source, msg) }

  function handleProcessStderr(text, defaultSource) {
    if (!text) return
    var lines = String(text).split("\n")
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim()
      if (!line) continue
      var match = line.match(/^(?:\[([0-9T:\-\.Z]+)\]\s+)?\[(ERROR|WARN|INFO|DEBUG|TRACE)\]\s+\[([^\]]+)\]\s+(.*)$/i)
      if (match) {
        var ts = match[1] || new Date().toISOString()
        var lvl = match[2].toUpperCase()
        var src = match[3]
        var msg = match[4]
        var entry = {
          timestamp: ts,
          level: lvl,
          source: src,
          message: root.sanitizeLog(msg)
        }
        var buf = root.logBuffer.slice()
        buf.push(entry)
        if (buf.length > 500) buf.shift()
        root.logBuffer = buf
        if (lvl === "ERROR") console.error(line)
        else if (lvl === "WARN") console.warn(line)
        else console.log(line)
      } else {
        var isInfo = line.startsWith("•") || line.startsWith("✓") ||
                     line.indexOf("Waiting for security key touch") !== -1 ||
                     line.indexOf("Requesting WebAuthn challenge") !== -1 ||
                     line.indexOf("Security key verified") !== -1
        if (isInfo) {
          root.logInfo(defaultSource || "omawarden:cli", line)
        } else {
          root.logError(defaultSource || "omawarden:cli", line)
        }
      }
    }
  }

  function filterVaultItems(resetSelection) {
    var currentId = (root.selectedItem && !resetSelection) ? root.selectedItem.id : null
    root.filteredItems = VaultSearch.filterItems(root.rawVaultItems, root.searchQuery, {
      vaultScope: root.activeVaultScope,
      folderScope: root.activeFolderScope,
      category: root.activeCategory
    })
    root.selectedIndex = VaultSearch.indexOfItem(root.filteredItems, currentId)
    root.handleSelectedItemChanged()
  }

  function getAvailableVaultScopes() {
    var items = root.rawVaultItems || []
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
      { id: "personal", name: "Personal Vault", icon: "\uf007", count: personalCount }
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

  function getAvailableFolderScopes() {
    var items = root.rawVaultItems || []
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

  onSearchQueryChanged: filterVaultItems(true)
  onActiveCategoryChanged: filterVaultItems(true)
  onActiveVaultScopeChanged: filterVaultItems(true)
  onActiveFolderScopeChanged: filterVaultItems(true)
  onSelectedIndexChanged: root.handleSelectedItemChanged()

  // Selecting an item never releases a secret; the release controller drops
  // the previous item's revealed values when its id changes.
  function handleSelectedItemChanged() {
    root.updateAvailableActions()
  }

  function canToggleReveal() {
    return root.showPasswordHistoryModal || root.isSelectionReady()
  }

  // Ctrl+T: hides whatever is revealed, otherwise reveals the item's primary
  // secret (one release). In the history modal it toggles the entries.
  function toggleItemRevealed() {
    if (root.showPasswordHistoryModal) {
      if (passwordHistoryModalComponent) passwordHistoryModalComponent.toggleAllRevealed()
      return
    }
    if (!root.isSelectionReady()) return
    if (secretRelease.hasRequestedValues()) {
      secretRelease.concealAll()
      return
    }
    secretRelease.reveal(SecretFieldCatalog.primarySecretField(root.selectedItem))
  }

  function updateAvailableActions() {
    root.currentAvailableActions = root.getAvailableActions(root.selectedItem)
  }

  onShowActionPaletteChanged: {
    if (root.showActionPalette) {
      root.updateAvailableActions()
    } else if (!root.hasActiveModal) {
      root.restoreSearchFocus()
    }
  }

  onShowPasswordHistoryModalChanged: {
    if (root.showPasswordHistoryModal) return
    secretRelease.conceal(SecretFieldCatalog.PASSWORD_HISTORY)
    root.activePasswordHistoryItem = null
    if (!root.hasActiveModal) root.restoreSearchFocus()
  }

  onShowPasswordGeneratorModalChanged: {
    if (!root.showPasswordGeneratorModal && !root.hasActiveModal) {
      root.restoreSearchFocus()
    }
  }

  function openPasswordGeneratorModal(mode) {
    root.passwordGeneratorModalMode = mode || "password"
    root.showActionPalette = false
    root.showPasswordGeneratorModal = true
  }

  onSelectedItemChanged: root.handleSelectedItemChanged()

  function cycleCategory(forward) {
    var idx = root.categoryList.indexOf(root.activeCategory)
    if (idx === -1) idx = 0
    if (forward) {
      idx = (idx + 1) % root.categoryList.length
    } else {
      idx = (idx - 1 + root.categoryList.length) % root.categoryList.length
    }
    root.activeCategory = root.categoryList[idx]
  }

  function copyToClipboard(text, isSensitive, label) {
    if (!text) return
    if (root.cliHealth && root.cliHealth.clipboard_available === false) {
      root.errorMessage = "Wayland clipboard utility 'wl-copy' not found. Please install 'wl-clipboard'."
      root.logWarn("omarchy:clipboard", root.errorMessage)
      return
    }
    root.logInfo("omarchy:clipboard", "Copying " + (label || "item") + " to clipboard (sensitive: " + isSensitive + ")")
    var cmd = [root.helperPath, "copy", "--stdin"]
    if (isSensitive) {
      cmd.push("--sensitive")
    }
    var ttl = (root.config && root.config.clipboard_clear_seconds) || 30
    if (ttl) {
      cmd.push("--timeout", String(ttl))
    }
    clipCopyProc.secret = JSON.stringify({ text: String(text) })
    clipCopyProc.command = cmd
    clipCopyProc.running = true
    root.statusMessage = "Copied " + (label || "value") + " to clipboard" + (isSensitive ? (" (clears in " + ttl + "s)") : "") + "."
  }

  // Secret copies name the field; the daemon writes the value to the
  // clipboard with the sensitive hint and schedules the auto-clear.
  function copySecretField(item, field, label) {
    if (!item || !SecretFieldCatalog.isPresent(item, field)) return false
    if (root.cliHealth && root.cliHealth.clipboard_available === false) {
      root.errorMessage = "Wayland clipboard utility 'wl-copy' not found. Please install 'wl-clipboard'."
      return true
    }
    secretRelease.copyField(field, label || SecretFieldCatalog.fieldLabel(item, field))
    return true
  }

  function copyPrimaryLoginSecret(item) {
    if (root.copySecretField(item, SecretFieldCatalog.LOGIN_PASSWORD, "password")) return
    if (item.login && item.login.username) root.copyToClipboard(item.login.username, false, "username")
  }

  function copyPrimaryIdentityValue(item) {
    var identity = item.identity || {}
    var name = ((identity.firstName || "") + " " + (identity.lastName || "")).trim()
    if (identity.email) root.copyToClipboard(identity.email, false, "identity email")
    else if (name) root.copyToClipboard(name, false, "name")
  }

  function copyPrimaryNoteSecret(item) {
    var field = SecretFieldCatalog.primarySecretField(item)
    if (field) root.copySecretField(item, field, "")
  }

  // Enter: logins copy the password, cards the number, notes the note (or the
  // first custom field), identities the email or name.
  function executePrimaryAction(item) {
    if (!item) return
    var handlers = {
      "login": root.copyPrimaryLoginSecret,
      "card": function(target) { root.copySecretField(target, SecretFieldCatalog.CARD_NUMBER, "card number") },
      "identity": root.copyPrimaryIdentityValue
    }
    var handler = handlers[item.type_name] || root.copyPrimaryNoteSecret
    handler(item)
  }

  function copyItemUsername(item) {
    if (!item) return
    var uName = ""
    if (item.type_name === "login" && item.login && item.login.username) {
      uName = item.login.username
    } else if (item.type_name === "identity" && item.identity) {
      uName = item.identity.username || item.identity.email || ""
    } else if (item.type_name === "card" && item.card && item.card.cardholderName) {
      uName = item.card.cardholderName
    }
    if (uName) {
      root.copyToClipboard(uName, false, "username")
    } else {
      root.errorMessage = "No username found for '" + item.name + "'."
      root.logWarn("omarchy:clipboard", root.errorMessage)
    }
  }

  // Ctrl+Enter: the daemon copies the current code; nothing is revealed.
  function copyItemTotp(item) {
    root.copySecretField(item, SecretFieldCatalog.LOGIN_TOTP, "TOTP code")
  }

  // The only path to Qt.openUrlExternally: http and https URLs only.
  function openUri(uri) {
    var url = UriPolicy.openableUrl(uri)
    if (!url) {
      root.statusMessage = root.strings.t("status.no_openable_uri", "This item has no http or https link to open.")
      return false
    }
    Qt.openUrlExternally(url)
    return true
  }

  function openFirstWebsite(item) {
    if (!item) return
    var url = UriPolicy.firstOpenableUrl(item)
    if (url) root.openUri(url)
    else root.statusMessage = root.strings.t("status.no_openable_uri", "This item has no http or https link to open.")
  }

  function openPasswordHistory(item) {
    if (!SecretFieldCatalog.isPresent(item, SecretFieldCatalog.PASSWORD_HISTORY)) {
      root.statusMessage = root.strings.t("status.no_password_history", "No password history is recorded for this item.")
      return
    }
    root.activePasswordHistoryItem = item
    root.showPasswordHistoryModal = true
    secretRelease.reveal(SecretFieldCatalog.PASSWORD_HISTORY)
  }

  function paletteAction(label, icon, shortcut, run) {
    return { label: label, icon: icon, shortcut: shortcut, action: run }
  }

  // Copies of public values: entries without a value are left out.
  function publicCopyActions(entries) {
    return entries.filter(function(entry) { return Boolean(entry.value) }).map(function(entry) {
      return root.paletteAction(entry.label, entry.icon, entry.shortcut || "", function() {
        root.copyToClipboard(String(entry.value), false, entry.copyLabel)
      })
    })
  }

  // Copies of secrets through copy-field: entries whose flag is false are
  // left out, and no label carries a secret value.
  function secretCopyActions(item, entries) {
    return entries.filter(function(entry) { return SecretFieldCatalog.isPresent(item, entry.field) }).map(function(entry) {
      return root.paletteAction(entry.label, entry.icon, entry.shortcut || "", function() {
        root.copySecretField(item, entry.field, entry.copyLabel)
      })
    })
  }

  function uriActions(item) {
    var assignedShortcut = false
    return UriPolicy.itemUris(item).map(function(entry) {
      if (!entry.isOpenable) {
        return root.paletteAction("Copy URI (" + entry.uri + ")", "\uf0c5", "", function() { root.copyToClipboard(entry.uri, false, "URI") })
      }
      var shortcut = assignedShortcut ? "" : "Ctrl+O"
      assignedShortcut = true
      return root.paletteAction("Open Website (" + entry.uri + ")", "\uf08e", shortcut, function() { root.openUri(entry.uri) })
    })
  }

  function passwordHistoryActions(item) {
    if (!SecretFieldCatalog.isPresent(item, SecretFieldCatalog.PASSWORD_HISTORY)) return []
    var count = Number(item.login.password_history_count) || 0
    return [root.paletteAction("Password History (" + count + ")", "\uf1da", "Ctrl+H", function() { root.openPasswordHistory(item) })]
  }

  function loginActions(item) {
    var login = item.login || {}
    return root.secretCopyActions(item, [
      { label: "Copy Password", icon: "\uf023", shortcut: "↵", field: SecretFieldCatalog.LOGIN_PASSWORD, copyLabel: "password" }
    ]).concat(root.publicCopyActions([
      { label: "Copy Username (" + login.username + ")", icon: "\uf007", shortcut: "Ctrl+U", value: login.username, copyLabel: "username" }
    ])).concat(root.secretCopyActions(item, [
      { label: "Copy TOTP Code", icon: "\uf017", shortcut: "Ctrl+↵", field: SecretFieldCatalog.LOGIN_TOTP, copyLabel: "TOTP code" }
    ])).concat(root.uriActions(item)).concat(root.passwordHistoryActions(item))
  }

  function cardActions(item) {
    var card = item.card || {}
    var expiry = (card.expMonth && card.expYear) ? (card.expMonth + "/" + card.expYear) : ""
    return root.secretCopyActions(item, [
      { label: "Copy Card Number", icon: "\uf09d", shortcut: "↵", field: SecretFieldCatalog.CARD_NUMBER, copyLabel: "card number" },
      { label: "Copy Security Code (CVV)", icon: "\uf292", field: SecretFieldCatalog.CARD_CODE, copyLabel: "security code" }
    ]).concat(root.publicCopyActions([
      { label: "Copy Cardholder Name", icon: "\uf007", value: card.cardholderName, copyLabel: "cardholder" },
      { label: "Copy Expiration (" + expiry + ")", icon: "\uf073", value: expiry, copyLabel: "expiration" }
    ]))
  }

  function identityActions(item) {
    var identity = item.identity || {}
    var fullName = ((identity.firstName || "") + " " + (identity.lastName || "")).trim()
    var address = [identity.address1, identity.city, identity.state, identity.postalCode, identity.country].filter(Boolean).join(", ")
    return root.publicCopyActions([
      { label: "Copy Full Name (" + fullName + ")", icon: "\uf007", value: fullName, copyLabel: "full name" },
      { label: "Copy Username (" + identity.username + ")", icon: "\uf02b", shortcut: "Ctrl+U", value: identity.username, copyLabel: "username" },
      { label: "Copy Email (" + identity.email + ")", icon: "\uf0e0", shortcut: "↵", value: identity.email, copyLabel: "email" },
      { label: "Copy Phone (" + identity.phone + ")", icon: "\uf095", value: identity.phone, copyLabel: "phone" },
      { label: "Copy Company (" + identity.company + ")", icon: "\uf1ad", value: identity.company, copyLabel: "company" },
      { label: "Copy Address (" + address + ")", icon: "\uf041", value: address, copyLabel: "address" }
    ]).concat(root.secretCopyActions(item, [
      { label: "Copy SSN", icon: "\uf292", field: SecretFieldCatalog.IDENTITY_SSN, copyLabel: "social security number" },
      { label: "Copy Passport Number", icon: "\uf2c2", field: SecretFieldCatalog.IDENTITY_PASSPORT_NUMBER, copyLabel: "passport number" },
      { label: "Copy Driver License", icon: "\uf2c2", field: SecretFieldCatalog.IDENTITY_LICENSE_NUMBER, copyLabel: "license number" }
    ]))
  }

  function customFieldActions(item) {
    return SecretFieldCatalog.customFieldsWithValue(item).map(function(field) {
      var name = field.name ? String(field.name) : "field value"
      var icon = SecretFieldCatalog.isHiddenCustomField(field) ? "\uf292" : "\uf02b"
      return root.paletteAction("Copy " + name, icon, "", function() {
        root.copySecretField(item, SecretFieldCatalog.customFieldIdentifier(field.index), name)
      })
    })
  }

  function typeSpecificActions(item) {
    var builders = { "login": root.loginActions, "card": root.cardActions, "identity": root.identityActions }
    var builder = builders[item.type_name]
    return builder ? builder(item) : []
  }

  function itemDetailActions(item) {
    return root.secretCopyActions(item, [
      { label: "Copy Notes", icon: "\uf0f6", field: SecretFieldCatalog.NOTES, copyLabel: "notes" }
    ]).concat(root.customFieldActions(item)).concat(root.publicCopyActions([
      { label: "Copy Folder (" + item.folder_name + ")", icon: "\uf07b", value: item.folder_name, copyLabel: "folder name" },
      { label: "Copy Organization (" + item.organization_name + ")", icon: "\uf1ad", value: item.organization_name, copyLabel: "organization name" }
    ])).concat([
      root.paletteAction("Toggle Field Visibility", "\uf06e", "Ctrl+T", function() { root.toggleItemRevealed() }),
      root.paletteAction("Copy Item Name (" + item.name + ")", "\uf0c5", "", function() { root.copyToClipboard(item.name, false, "item name") })
    ])
  }

  function itemScopeActions(item) {
    var actions = []
    if (item.organization_id && root.activeVaultScope !== item.organization_id) {
      actions.push(root.paletteAction("Filter by this Vault (" + (item.organization_name || "Organization") + ")", "\uf1ad", "", function() { root.activeVaultScope = item.organization_id }))
    }
    if (item.folder_id && root.activeFolderScope !== item.folder_id) {
      actions.push(root.paletteAction("Filter by this Folder (" + (item.folder_name || "Folder") + ")", "\uf07b", "", function() { root.activeFolderScope = item.folder_id }))
    }
    return actions
  }

  function vaultScopeActions(excludedScope) {
    return root.getAvailableVaultScopes().filter(function(scope) {
      return scope.id !== root.activeVaultScope && !(excludedScope && scope.id === excludedScope)
    }).map(function(scope) {
      return root.paletteAction("Filter Vault: " + scope.name, scope.icon, scope.id === "all" ? "Alt+V" : "", function() { root.activeVaultScope = scope.id })
    })
  }

  function folderScopeActions(excludedScope) {
    return root.getAvailableFolderScopes().filter(function(scope) {
      return scope.id !== root.activeFolderScope && !(excludedScope && scope.id === excludedScope)
    }).map(function(scope) {
      return root.paletteAction("Filter Folder: " + scope.name, scope.icon, scope.id === "all" ? "Alt+F" : "", function() { root.activeFolderScope = scope.id })
    })
  }

  function clearScopeActions() {
    if (root.activeVaultScope === "all" && root.activeFolderScope === "all") return []
    return [root.paletteAction("Clear Scope Filters", "\uf00d", "Esc", function() {
      root.activeVaultScope = "all"
      root.activeFolderScope = "all"
    })]
  }

  function scopeFilterActions(item) {
    var excludedVault = item ? item.organization_id : ""
    var excludedFolder = item ? item.folder_id : ""
    return root.vaultScopeActions(excludedVault).concat(root.folderScopeActions(excludedFolder)).concat(root.clearScopeActions())
  }

  function generalActions() {
    return [
      root.paletteAction("Generate Password", "\uf084", "Ctrl+G", function() { root.openPasswordGeneratorModal("password") }),
      root.paletteAction("Generate Passphrase", "\uf02d", "", function() { root.openPasswordGeneratorModal("passphrase") }),
      root.paletteAction("Sync Vault Now", "\uf021", "Ctrl+R", function() { root.syncVault(false, true) }),
      root.paletteAction("Lock Vault", "\uf023", "Ctrl+L", function() { root.doLock() })
    ]
  }

  function getAvailableActions(item) {
    if (!item) return root.generalActions().concat(root.scopeFilterActions(null))
    return root.typeSpecificActions(item)
      .concat(root.itemDetailActions(item))
      .concat(root.itemScopeActions(item))
      .concat(root.scopeFilterActions(item))
      .concat(root.generalActions())
  }

  function saveSettings(settings) {
    root.configSeq++
    root.isBusy = true
    root.logInfo("omarchy:settings", "Saving configuration (log_level: " + (settings.log_level || "error") + ")...")
    root.statusMessage = "Saving configuration..."
    var cmd = [root.helperPath, "config", "set"]
    if (settings.server_url !== undefined) cmd.push("--server-url", settings.server_url)
    if (settings.identity_url !== undefined) cmd.push("--identity-url", settings.identity_url)
    if (settings.client_cert_path !== undefined) cmd.push("--client-cert", settings.client_cert_path)
    if (settings.client_key_path !== undefined) cmd.push("--client-key", settings.client_key_path)
    if (settings.auto_lock_minutes !== undefined) cmd.push("--auto-lock", String(settings.auto_lock_minutes))
    if (settings.clipboard_clear_seconds !== undefined) cmd.push("--clipboard-clear", String(settings.clipboard_clear_seconds))
    if (settings.log_level !== undefined) cmd.push("--log-level", settings.log_level)
    if (settings.remember_last_search !== undefined) cmd.push("--remember-last-search", String(settings.remember_last_search))
    if (settings.quick_unlock !== undefined) cmd.push("--quick-unlock", String(settings.quick_unlock))

    configSetProc.command = cmd
    configSetProc.running = true
  }

  function copyDiagnostics() {
    var ts = new Date().toISOString()
    var cliVer = (root.cliHealth && root.cliHealth.version) ? root.cliHealth.version : "Unknown"
    var rawUrl = (root.config && root.config.server_url) ? root.config.server_url : ""
    var sUrl = root.sanitizeServerUrl(rawUrl)
    var rawIdUrl = (root.config && root.config.identity_url) ? root.config.identity_url : ""
    var idUrl = rawIdUrl ? root.sanitizeServerUrl(rawIdUrl) : "Auto"
    var lLevel = (root.config && root.config.log_level) ? root.config.log_level : "error"
    var vStatus = (root.authState ? root.authState.status : "unknown")

    var report = "### Omarchy Bitwarden Diagnostics Report\n\n"
    report += "- **Generated At**: " + ts + "\n"
    report += "- **omawarden Version**: " + cliVer + "\n"
    report += "- **Server URL**: " + sUrl + "\n"
    report += "- **Identity URL**: " + idUrl + "\n"
    var hasCert = Boolean(root.config && root.config.client_cert_path)
    report += "- **mTLS Configured**: " + (hasCert ? "Yes" : "No") + "\n"
    report += "- **Configured Log Level**: " + lLevel + "\n"
    report += "- **Vault Status**: " + vStatus + "\n"
    report += "- **Engine Ready**: " + (root.cliHealth && root.cliHealth.installed ? "Yes" : "No") + "\n"
    var engineSourceStr = root.engineSource ? root.engineSource.toUpperCase() : "AUR"
    if (root.enginePackage) {
      engineSourceStr += " (" + root.enginePackage + ")"
    } else if (root.engineSource === "system") {
      engineSourceStr += " (system binary)"
    }
    report += "- **Engine Source**: " + engineSourceStr + "\n"
    report += "- **Engine Binary Path**: " + (root.helperPath || "Unknown") + "\n"
    report += "- **Keyring Available**: " + (root.cliHealth && root.cliHealth.keyring_available ? "Yes" : "No") + "\n"
    report += "- **Clipboard Available**: " + (root.cliHealth && root.cliHealth.clipboard_available ? "Yes" : "No") + "\n\n"
    report += "#### Recent Logs (" + (root.logBuffer ? root.logBuffer.length : 0) + " entries):\n\n```text\n"

    var logs = root.logBuffer || []
    var recent = logs.slice(-50)
    for (var i = 0; i < recent.length; i++) {
      var item = recent[i]
      report += "[" + item.timestamp + "] [" + item.level + "] [" + item.source + "] " + item.message + "\n"
    }
    if (recent.length === 0) {
      report += "(No logs recorded yet)\n"
    }
    report += "```\n"

    root.copyToClipboard(report, false, "Diagnostics report")
    root.statusMessage = "Diagnostics report copied to clipboard."
  }

  function doUnlock(password) {
    if (!password) return
    root.logInfo("omarchy:auth", "Submitting unlock request...")
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Unlocking vault..."
    authUnlockProc.secret = password
    authUnlockProc.command = [root.helperPath, "auth", "unlock"]
    authUnlockProc.running = true
  }

  function doQuickUnlock() {
    root.logInfo("omarchy:auth", "Submitting quick unlock request...")
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Waiting for system authentication..."
    authUnlockProc.secret = ""
    authUnlockProc.command = [root.helperPath, "auth", "quick-unlock"]
    authUnlockProc.running = true
  }

  // Drops all vault state and shows the unlock view (the session is kept).
  function markVaultLocked() {
    root.clearSensitiveState()
    root.authState = ({
      status: "locked",
      server_url: (root.authState && root.authState.server_url) || "",
      user_email: (root.authState && root.authState.user_email) || "",
      has_session: Boolean(root.authState && root.authState.has_session)
    })
    root.currentView = "auto"
  }

  // A refused release. release_limit_exceeded and vault_locked mean the
  // daemon is locked now, so the overlay returns to the unlock view.
  function handleReleaseRefusal(errorCode, message) {
    root.errorMessage = message
    root.logWarn("omarchy:secrets", "Secret release refused (" + (errorCode || "no error code") + ")")
    if (!SecretFieldCatalog.errorLocksVault(errorCode)) return
    root.markVaultLocked()
    root.refreshAuthStatus()
  }

  function confirmSecretCopy(label, clearSeconds) {
    var seconds = clearSeconds > 0 ? clearSeconds : root.clipboardClearSeconds()
    root.statusMessage = root.strings.t("status.secret_copied", "Copied %1 to the clipboard (clears in %2 s).").arg(label).arg(seconds)
  }

  function clipboardClearSeconds() {
    var configured = root.config ? Number(root.config.clipboard_clear_seconds) : 0
    return configured > 0 ? configured : root.defaultClipboardClearSeconds
  }

  function doLock() {
    root.logInfo("omarchy:auth", "Locking vault...")
    root.markVaultLocked()
    root.isBusy = true
    root.statusMessage = "Locking vault..."
    authLockProc.command = [root.helperPath, "auth", "lock"]
    authLockProc.running = true
  }

  function doLoginPassword(email, password, code, provider) {
    if (!email || !password) return
    var effectiveProvider = (provider !== undefined && provider !== null)
        ? provider
        : root.twoFactorProvider
    root.twoFactorProvider = effectiveProvider
    if (authViewComponent) {
      authViewComponent.twoFactorProvider = effectiveProvider
    }
    root.logInfo("omarchy:auth", "Submitting password login (provider: " + effectiveProvider + ")...")
    root.isBusy = true
    root.errorMessage = ""
    if (root.show2FAField && effectiveProvider === 7) {
      root.statusMessage = "Waiting for security key touch..."
    } else {
      root.statusMessage = "Logging in to Bitwarden..."
    }
    var cmd = [root.helperPath, "auth", "login-password", "--email", email]
    if (root.rememberEmailChecked) {
      cmd.push("--remember-email", "true")
    } else {
      cmd.push("--remember-email", "false")
    }
    if (code || (root.show2FAField && effectiveProvider === 7)) {
      var payload = { password: password }
      if (code) {
        payload.code = code
      }
      if (root.isNewDeviceVerification) {
        payload.new_device_otp = code
      }
      if (effectiveProvider !== undefined && effectiveProvider !== null) {
        payload.two_factor_provider = effectiveProvider
      }
      authLoginProc.secret = JSON.stringify(payload)
    } else {
      authLoginProc.secret = JSON.stringify({ password: password })
    }
    authLoginProc.command = cmd
    authLoginProc.running = true
  }

  function doLoginApiKey(clientId, clientSecret) {
    if (!clientId || !clientSecret) return
    root.logInfo("omarchy:auth", "Submitting API Key login...")
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Authenticating with API Key..."
    authLoginProc.secret = clientSecret
    authLoginProc.command = [root.helperPath, "auth", "login-apikey", "--client-id", clientId]
    authLoginProc.running = true
  }

  function doSendTwoFactorEmail(email, password) {
    if (!email || !password) {
      root.errorMessage = "Email and password are required to send verification code."
      if (authViewComponent) {
        authViewComponent.notifyEmailCodeFailed()
      }
      return
    }
    root.logInfo("omarchy:auth", "Submitting send two-factor email request...")
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Sending verification email..."
    authSendEmailProc.secret = JSON.stringify({ password: password })
    authSendEmailProc.command = [root.helperPath, "auth", "send-two-factor-email", "--email", email]
    authSendEmailProc.running = true
  }

  function doCheckFido2Status() {
    if (authFido2CheckProc.running) return
    authFido2CheckProc.command = [root.helperPath, "auth", "fido2-status"]
    authFido2CheckProc.running = true
  }

  function doLogout() {
    root.logInfo("omarchy:auth", "Logging out session...")
    root.clearSensitiveState()
    root.show2FAField = false
    root.isNewDeviceVerification = false
    root.twoFactorProvider = 0
    root.availableTwoFactorProviders = []
    root.fido2Status = ""
    if (authViewComponent) {
      authViewComponent.show2FAField = false
      authViewComponent.isNewDeviceVerification = false
      authViewComponent.twoFactorProvider = 0
      authViewComponent.availableTwoFactorProviders = []
      authViewComponent.fido2Status = ""
    }
    root.authState = ({
      status: "unauthenticated",
      server_url: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "",
      user_email: "",
      has_session: false
    })
    root.isBusy = true
    root.statusMessage = "Logging out..."
    authLogoutProc.command = [root.helperPath, "auth", "logout"]
    authLogoutProc.running = true
  }

  Timer {
    id: statusMessageTimer
    interval: 3000
    repeat: false
    onTriggered: root.statusMessage = ""
  }

  onStatusMessageChanged: {
    if (root.statusMessage !== "") {
      statusMessageTimer.restart()
    }
  }

  Timer {
    id: lockSyncTimer
    interval: 3000
    running: Boolean(root.opened && root.authState && root.authState.status === "unlocked")
    repeat: true
    onTriggered: root.refreshAuthStatus()
  }

  // ---- Keyboard dispatch (the Shortcut elements above cover most chords
  // while the search field has focus; this handles the rest) ----

  function isSearchReady() {
    return root.effectiveView === "search" && !root.hasActiveModal
  }

  function isSelectionReady() {
    return root.isSearchReady() && root.selectedItem !== null
  }

  function canSyncNow() {
    var status = root.authState ? root.authState.status : ""
    var hasSession = Boolean(root.authState && root.authState.has_session)
    return (status === "unlocked" || (status === "locked" && hasSession)) && !root.isBusy && !root.hasActiveModal
  }

  function isUnlockedWithoutModal() {
    return Boolean(root.authState && root.authState.status === "unlocked") && !root.hasActiveModal
  }

  function isRevealShortcut(event) {
    var isLetterT = event.key === Qt.Key_T || (Boolean(event.text) && event.text.toLowerCase() === "t")
    return Boolean(event.modifiers & Qt.ControlModifier) && isLetterT
  }

  function openActionPalette() {
    root.actionPaletteIndex = 0
    root.showActionPalette = true
  }

  function toggleSettingsView() {
    root.currentView = (root.effectiveView === "settings") ? "auto" : "settings"
  }

  // Esc outside modals: leave settings, close a scope dropdown, clear the
  // query, clear the scope filters, then hide the overlay.
  function handleEscape() {
    if (root.effectiveView === "settings") {
      root.currentView = "auto"
    } else if (searchHeader && (searchHeader.isVaultScopeOpen || searchHeader.isFolderScopeOpen)) {
      searchHeader.closeScopeDropdowns()
    } else if (root.searchQuery && root.searchQuery.length > 0) {
      root.searchQuery = ""
      if (searchHeader) searchHeader.clearSearchRequested()
    } else if (root.activeVaultScope !== "all" || root.activeFolderScope !== "all") {
      root.activeVaultScope = "all"
      root.activeFolderScope = "all"
    } else {
      root.dismiss()
    }
    return true
  }

  // Modals take only Esc here; every other key is left to them.
  function handleModalKey(event) {
    if (event.key !== Qt.Key_Escape) return false
    if (root.showActionPalette) root.showActionPalette = false
    else if (root.showPasswordHistoryModal) root.showPasswordHistoryModal = false
    else root.showPasswordGeneratorModal = false
    return true
  }

  function handleScopeKey(event) {
    var openers = {}
    openers[Qt.Key_V] = function() { searchHeader.openVaultScope() }
    openers[Qt.Key_F] = function() { searchHeader.openFolderScope() }
    var opener = openers[event.key]
    if (!opener || !searchHeader || !root.isSearchReady()) return false
    opener()
    return true
  }

  // Enter copies the primary secret, Ctrl+Enter the TOTP code. A held key
  // repeats; only the first press copies, so auto-repeat cannot drain the
  // release budget.
  function handlePrimaryKey(event) {
    if (root.effectiveView !== "search" || !root.selectedItem) return false
    if (event.isAutoRepeat) return true
    if (event.modifiers & Qt.ControlModifier) root.copyItemTotp(root.selectedItem)
    else root.executePrimaryAction(root.selectedItem)
    return true
  }

  function moveSelection(step) {
    var count = root.filteredItems.length
    if (count > 0) root.selectedIndex = (root.selectedIndex + step + count) % count
    return true
  }

  function handleNavigationKey(event) {
    if (root.effectiveView !== "search") return false
    var steps = {}
    steps[Qt.Key_Tab] = function() { root.cycleCategory(true); return true }
    steps[Qt.Key_Backtab] = function() { root.cycleCategory(false); return true }
    steps[Qt.Key_Down] = function() { return root.moveSelection(1) }
    steps[Qt.Key_Up] = function() { return root.moveSelection(-1) }
    var step = steps[event.key]
    return step ? step() : false
  }

  // Ctrl+<key> -> [precondition, action].
  function controlKeyAction(key) {
    var actions = {}
    actions[Qt.Key_U] = [root.isSelectionReady, function() { root.copyItemUsername(root.selectedItem) }]
    actions[Qt.Key_K] = [root.isSearchReady, root.openActionPalette]
    actions[Qt.Key_G] = [root.isSearchReady, function() { root.openPasswordGeneratorModal("password") }]
    actions[Qt.Key_O] = [root.isSelectionReady, function() { root.openFirstWebsite(root.selectedItem) }]
    actions[Qt.Key_H] = [root.isSelectionReady, function() { root.openPasswordHistory(root.selectedItem) }]
    actions[Qt.Key_L] = [root.isUnlockedWithoutModal, root.doLock]
    actions[Qt.Key_R] = [root.canSyncNow, function() { root.syncVault(false, true) }]
    actions[Qt.Key_Comma] = [function() { return !root.hasActiveModal }, root.toggleSettingsView]
    return actions[key] || null
  }

  // A held chord repeats. Each Ctrl action (opening a website, copying,
  // opening a view, locking, syncing) acts once per press; repeats are
  // accepted and ignored, so a held Ctrl+O opens one browser tab.
  function handleControlKey(event) {
    var entry = root.controlKeyAction(event.key)
    if (!entry || !entry[0]()) return false
    if (!event.isAutoRepeat) entry[1]()
    return true
  }

  function handleUnmodalKey(event) {
    var keyHandlers = {}
    keyHandlers[Qt.Key_Escape] = root.handleEscape
    keyHandlers[Qt.Key_Return] = root.handlePrimaryKey
    keyHandlers[Qt.Key_Enter] = root.handlePrimaryKey
    var handler = keyHandlers[event.key]
    if (handler) return handler(event)
    if (root.handleNavigationKey(event)) return true
    return Boolean(event.modifiers & Qt.ControlModifier) && root.handleControlKey(event)
  }

  // Returns true when the key was handled. A held Ctrl+T would alternate
  // reveal and conceal, one release per repeat, so repeats are ignored.
  function handleOverlayKey(event) {
    if (root.isRevealShortcut(event) && root.canToggleReveal()) {
      if (!event.isAutoRepeat) root.toggleItemRevealed()
      return true
    }
    if ((event.modifiers & Qt.AltModifier) && root.handleScopeKey(event)) return true
    if (root.hasActiveModal) return root.handleModalKey(event)
    return root.handleUnmodalKey(event)
  }

  function restoreSearchFocus(cursorAtEnd) {
    var atEnd = (cursorAtEnd === true)
    Qt.callLater(function() {
      if (root.opened && root.effectiveView === "search") {
        if (focusRoot) focusRoot.forceActiveFocus()
        if (searchHeader) searchHeader.focusSearch(atEnd)
      } else if (root.opened && (root.effectiveView === "unlock" || root.effectiveView === "login") && authViewComponent && authViewComponent.unlockInput) {
        authViewComponent.unlockInput.forceActiveFocus()
      }
    })
  }

  // ======================================================
  // FLOATING OVERLAY WINDOW
  // ======================================================
  FloatingWindow {
    id: panel
    title: "Bitwarden"
    visible: root.opened
    color: root.background
    implicitWidth: 880
    implicitHeight: 560
    minimumSize: Qt.size(720, 480)

    onVisibleChanged: {
      if (visible) {
        var canRemember = Boolean(root.config && root.config.remember_last_search === true && root.authState && root.authState.status === "unlocked")
        root.restoreSearchFocus(canRemember)
        if (root.effectiveView === "search" && root.selectedItem) {
          root.handleSelectedItemChanged()
        }
      } else if (root.opened) {
        // The compositor closed the window (close shortcut, titlebar) behind
        // our back. Without this, `opened` stays true and the next toggle
        // only hides a window that isn't there.
        root.dismiss()
      }
    }

    FocusScope {
      id: focusRoot
      anchors.fill: parent
      focus: true

      Shortcut {
        sequence: "Ctrl+K"
        enabled: root.opened && root.effectiveView === "search" && !root.hasActiveModal
        onActivated: {
          root.actionPaletteIndex = 0
          root.showActionPalette = true
        }
      }

      Shortcut {
        sequence: "Ctrl+G"
        enabled: root.opened && root.effectiveView === "search" && !root.hasActiveModal
        onActivated: {
          root.openPasswordGeneratorModal("password")
        }
      }

      Shortcut {
        sequences: ["Ctrl+Return", "Ctrl+Enter"]
        // Each activation is a budgeted release; a held chord must not repeat it.
        autoRepeat: false
        enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null && !root.hasActiveModal
        onActivated: root.copyItemTotp(root.selectedItem)
      }

      Shortcut {
        sequence: "Ctrl+U"
        enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null && !root.hasActiveModal
        onActivated: root.copyItemUsername(root.selectedItem)
      }

      Shortcut {
        sequence: "Ctrl+T"
        autoRepeat: false
        enabled: root.opened && (root.showPasswordHistoryModal || (root.effectiveView === "search" && root.selectedItem !== null && !root.hasActiveModal))
        onActivated: root.toggleItemRevealed()
      }

      Shortcut {
        sequence: "Ctrl+O"
        // Each activation opens a browser tab; a held chord must not repeat it.
        autoRepeat: false
        enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null && !root.hasActiveModal
        onActivated: root.openFirstWebsite(root.selectedItem)
      }

      Shortcut {
        sequence: "Ctrl+L"
        enabled: root.opened && root.authState.status === "unlocked" && !root.hasActiveModal
        onActivated: root.doLock()
      }

      Shortcut {
        sequence: "Ctrl+R"
        enabled: root.opened && (root.authState.status === "unlocked" || (root.authState.status === "locked" && root.authState.has_session)) && !root.isBusy && !root.hasActiveModal
        onActivated: root.syncVault(false, true)
      }

      Shortcut {
        sequence: "Ctrl+,"
        enabled: root.opened && !root.hasActiveModal
        onActivated: root.currentView = (root.effectiveView === "settings") ? "auto" : "settings"
      }

      Shortcut {
        sequence: "Alt+V"
        enabled: root.opened && root.effectiveView === "search" && !root.hasActiveModal
        onActivated: {
          if (searchHeader) searchHeader.openVaultScope()
        }
      }

      Shortcut {
        sequence: "Alt+F"
        enabled: root.opened && root.effectiveView === "search" && !root.hasActiveModal
        onActivated: {
          if (searchHeader) searchHeader.openFolderScope()
        }
      }

      Shortcut {
        sequence: "Escape"
        enabled: root.opened
        onActivated: {
          if (root.showPasswordGeneratorModal) {
            root.showPasswordGeneratorModal = false
          } else if (root.showPasswordHistoryModal) {
            root.showPasswordHistoryModal = false
          } else if (root.showActionPalette) {
            root.showActionPalette = false
          } else if (root.effectiveView === "settings") {
            root.currentView = "auto"
          } else if (searchHeader && (searchHeader.isVaultScopeOpen || searchHeader.isFolderScopeOpen)) {
            searchHeader.closeScopeDropdowns()
          } else if (root.searchQuery && root.searchQuery.length > 0) {
            root.searchQuery = ""
            if (searchHeader) searchHeader.clearSearchRequested()
          } else if (root.activeVaultScope !== "all" || root.activeFolderScope !== "all") {
            root.activeVaultScope = "all"
            root.activeFolderScope = "all"
          } else {
            root.dismiss()
          }
        }
      }

      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        if (root.handleOverlayKey(event)) event.accepted = true
      }

      ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 14
        anchors.rightMargin: 14
        anchors.topMargin: 14
        anchors.bottomMargin: 4
        spacing: 8

        // 1. Search & Category Header (Search View)
        SearchHeader {
          id: searchHeader
          visible: root.effectiveView === "search"
          modalsActive: root.hasActiveModal
          Layout.preferredHeight: visible ? implicitHeight : 0
          searchQuery: root.searchQuery
          categoryList: root.categoryList
          activeCategory: root.activeCategory
          activeVaultScope: root.activeVaultScope
          activeFolderScope: root.activeFolderScope
          rawVaultItems: root.rawVaultItems
          fontFamily: root.fontFamily
          background: root.background
          foreground: root.foreground
          accent: root.accent
          muted: root.muted
          borderColor: root.borderColor
          onSearchQueryChanged: root.searchQuery = searchQuery
          onCategorySelected: function(cat) { root.activeCategory = cat }
          onVaultScopeSelected: function(scope) { root.activeVaultScope = scope }
          onFolderScopeSelected: function(scope) { root.activeFolderScope = scope }
          onClearSearchRequested: {
            root.searchQuery = ""
            root.filterVaultItems()
          }
          onCopyUsernameRequested: {
            if (root.selectedItem) {
              root.copyItemUsername(root.selectedItem)
            }
          }
          onCopyTotpRequested: {
            if (root.selectedItem) {
              root.copyItemTotp(root.selectedItem)
            }
          }
          onOpenUrlRequested: {
            if (root.selectedItem) {
              root.openFirstWebsite(root.selectedItem)
            }
          }
          onActionPaletteRequested: {
            root.actionPaletteIndex = 0
            root.showActionPalette = true
          }
        }

        // 2. Main Content Center View
        Item {
          Layout.fillWidth: true
          Layout.fillHeight: true

          // Mode A: Search / Vault View (2-Column Split)
          RowLayout {
            anchors.fill: parent
            spacing: 12
            visible: root.effectiveView === "search"

            // Left Column: Items List
            VaultItemList {
              id: vaultItemList
              Layout.fillHeight: true
              Layout.preferredWidth: 320
              Layout.minimumWidth: 260
              Layout.maximumWidth: 320
              items: root.filteredItems
              selectedIndex: root.selectedIndex
              searchQuery: root.searchQuery
              activeVaultScope: root.activeVaultScope
              activeFolderScope: root.activeFolderScope
              fontFamily: root.fontFamily
              foreground: root.foreground
              accent: root.accent
              selectedText: root.accent
              muted: root.muted
              selectedBackground: root.selectedBackground
              borderColor: root.borderColor
              onItemSelected: function(idx) { root.selectedIndex = idx }
              onItemTriggered: function(idx) {
                root.selectedIndex = idx
                root.executePrimaryAction(root.selectedItem)
              }
            }

            // Vertical Divider
            Rectangle {
              Layout.fillHeight: true
              width: 1
              color: root.borderColor
            }

            // Right Column: Detail Inspector OR Empty Cheat Sheet
            Item {
              Layout.fillWidth: true
              Layout.fillHeight: true

              // Item Inspector View
              ItemInspector {
                anchors.fill: parent
                visible: root.selectedItem !== null
                item: root.selectedItem
                revealedValues: secretRelease.revealedValues
                requestedFields: secretRelease.requestedFields
                totpSecondsRemaining: secretRelease.totpSecondsRemaining
                totpPeriod: secretRelease.totpPeriod
                fontFamily: root.fontFamily
                foreground: root.foreground
                accent: root.accent
                muted: root.muted
                borderColor: root.borderColor
                onCopyRequested: function(text, isSensitive, label) { root.copyToClipboard(text, isSensitive, label) }
                onSecretCopyRequested: function(field, label) { root.copySecretField(root.selectedItem, field, label) }
                onRevealToggleRequested: function(field) { secretRelease.toggleReveal(field) }
                onOpenUriRequested: function(uri) { root.openUri(uri) }
                onPasswordHistoryRequested: function(item) { root.openPasswordHistory(item) }
              }

              // Empty Selection State View
              EmptyInspector {
                anchors.fill: parent
                visible: root.selectedItem === null
                rawVaultItems: root.rawVaultItems
                authState: root.authState
                fontFamily: root.fontFamily
                foreground: root.foreground
                accent: root.accent
                muted: root.muted
                borderColor: root.borderColor
              }
            }
          }

          // Mode B: Auth View (Unlock or Login)
          AuthView {
            id: authViewComponent
            anchors.fill: parent
            visible: root.effectiveView === "unlock" || root.effectiveView === "login"
            authState: root.authState
            config: root.config
            cliHealth: root.cliHealth
            isBusy: root.isBusy
            loginMethod: root.loginMethod
            rememberEmailChecked: root.rememberEmailChecked
            show2FAField: root.show2FAField
            isNewDeviceVerification: root.isNewDeviceVerification
            twoFactorProvider: root.twoFactorProvider
            availableTwoFactorProviders: root.availableTwoFactorProviders
            fido2Status: root.fido2Status
            fontFamily: root.fontFamily
            foreground: root.foreground
            accent: root.accent
            muted: root.muted
            borderColor: root.borderColor
            quickUnlockAvailable: root.quickUnlockReady
            onQuickUnlockRequested: root.doQuickUnlock()
            onUnlockRequested: function(pwd) { root.doUnlock(pwd) }
            onLoginPasswordRequested: function(email, pwd, code, prov) { root.doLoginPassword(email, pwd, code, prov) }
            onTwoFactorProviderSelected: function(prov) {
              root.twoFactorProvider = prov
              if (authViewComponent) {
                authViewComponent.twoFactorProvider = prov
              }
              if (prov === 7) {
                root.doCheckFido2Status()
              }
            }
            onCopyRequested: function(txt, lbl) { root.copyToClipboard(txt, false, lbl) }
            onLoginApiKeyRequested: function(cId, cSec) { root.doLoginApiKey(cId, cSec) }
            onSendTwoFactorEmailRequested: function(email, pwd) { root.doSendTwoFactorEmail(email, pwd) }
            onCheckFido2StatusRequested: { root.doCheckFido2Status() }
            onLogoutRequested: { root.doLogout() }
            onSettingsRequested: { root.currentView = "settings" }
            onServerConfigSaved: function(sUrl, cCert, cKey) {
              root.saveSettings({
                server_url: sUrl,
                client_cert_path: cCert,
                client_key_path: cKey
              })
            }
          }

          // Mode C: Settings View
          SettingsModal {
            id: settingsView
            anchors.fill: parent
            visible: root.effectiveView === "settings"
            config: root.config
            cliHealth: root.cliHealth
            engineSource: root.engineSource
            enginePackage: root.enginePackage
            logBuffer: root.logBuffer
            isBusy: root.isBusy
            fontFamily: root.fontFamily
            foreground: root.foreground
            accent: root.accent
            muted: root.muted
            borderColor: root.borderColor
            onSaveRequested: function(newSettings) { root.saveSettings(newSettings) }
            onCloseRequested: { root.currentView = "auto" }
            onRefreshHealthRequested: {
              root.checkDependencies()
            }
            onCopyDiagnosticsRequested: { root.copyDiagnostics() }
            onClearLogsRequested: { root.logBuffer = [] }
          }

          // Mode D: Dependency Check View (Prerequisite Setup)
          DependencyCheckView {
            id: dependencyCheckView
            anchors.fill: parent
            visible: root.effectiveView === "dependency_check"
            isChecking: root.isCheckingDependencies
            fontFamily: root.fontFamily
            foreground: root.foreground
            accent: root.accent
            muted: root.muted
            borderColor: root.borderColor
            onRecheckRequested: { root.checkDependencies() }
          }
        }

        // 3. Footer Bar (Bottom Left: Actions, Sync, Lock, Settings; Bottom Right: Versions & Actions)
        FooterBar {
          isUnlocked: root.effectiveView === "search"
          isBusy: root.isBusy
          overlayVersion: (root.manifest && root.manifest.version) ? (root.manifest.version) : ""
          backendVersion: (root.cliHealth && root.cliHealth.version) || ""
          isEngineInstalled: !root.dependenciesMissing && Boolean(root.cliHealth && root.cliHealth.installed)
          background: root.background
          fontFamily: root.fontFamily
          foreground: root.foreground
          accent: root.accent
          muted: root.muted
          borderColor: root.borderColor
          onActionPaletteTriggered: {
            root.actionPaletteIndex = 0
            root.showActionPalette = true
          }
          onGeneratePasswordTriggered: { root.openPasswordGeneratorModal("password") }
          onSyncTriggered: { root.syncVault(false, true) }
          onLockTriggered: { root.doLock() }
          onSettingsTriggered: root.currentView = (root.effectiveView === "settings") ? "auto" : "settings"
        }
      }

      // 4. Floating Top-Right Toast Alert (Prevents dynamic window shifting!)
      ToastAlert {
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.topMargin: 14
        anchors.rightMargin: 14
        statusMessage: root.statusMessage
        errorMessage: root.errorMessage
        isBusy: root.isBusy
        fontFamily: root.fontFamily
        foreground: root.foreground
        accent: root.accent
        onClearRequested: {
          root.statusMessage = ""
          root.errorMessage = ""
        }
      }

      // 5. Action Palette Modal Overlay (Ctrl+K)
      ActionPaletteModal {
        active: root.showActionPalette
        actions: root.currentAvailableActions
        fontFamily: root.fontFamily
        foreground: root.foreground
        accent: root.accent
        muted: root.muted
        cardBackground: Commons.Color.popups.background
        borderColor: Commons.Color.popups.border
        onActionSelected: function(actionItem) {
          root.showActionPalette = false
          if (actionItem && typeof actionItem.action === "function") {
            actionItem.action()
          }
        }
        onCloseRequested: { root.showActionPalette = false }
      }

      // 6. Password History Modal Overlay
      PasswordHistoryModal {
        id: passwordHistoryModalComponent
        active: root.showPasswordHistoryModal
        item: root.activePasswordHistoryItem
        historyEntries: secretRelease.passwordHistory
        fontFamily: root.fontFamily
        foreground: root.foreground
        accent: root.accent
        muted: root.muted
        cardBackground: Commons.Color.popups.background
        borderColor: Commons.Color.popups.border
        onCloseRequested: { root.showPasswordHistoryModal = false }
      }

      // 7. Password & Passphrase Generator Modal Overlay
      PasswordGeneratorModal {
        id: passwordGeneratorModalComponent
        active: root.showPasswordGeneratorModal
        mode: root.passwordGeneratorModalMode
        isEngineOutdated: root.isGeneratorEngineOutdated
        engineVersion: (root.cliHealth && root.cliHealth.version) || ""
        requiredVersion: root.minimumGeneratorEngineVersion
        fontFamily: root.fontFamily
        foreground: root.foreground
        accent: root.accent
        muted: root.muted
        cardBackground: Commons.Color.popups.background
        borderColor: Commons.Color.popups.border
        onGenerateRequested: function(opts) { root.generatePasswordOrPassphrase(opts) }
        onCopyRequested: function(text, isSensitive, label) { root.copyToClipboard(text, isSensitive, label) }
        onCloseRequested: {
          root.showPasswordGeneratorModal = false
          if (passwordGenProc.running) {
            passwordGenProc.isCanceled = true
            passwordGenProc.running = false
          }
        }
      }
    }
  }

  // ======================================================
  // QUICKSHELL IO BACKGROUND PROCESSES
  // ======================================================
  Process {
    id: passwordGenProc
    property bool isCanceled: false
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (!passwordGeneratorModalComponent) return
        passwordGeneratorModalComponent.isGenerating = false
        var out = (text || "").trim()
        if (out) {
          try {
            var data = JSON.parse(out)
            if (data && data.ok) {
              passwordGeneratorModalComponent.errorMessage = ""
              passwordGeneratorModalComponent.generatedPassword = data.password || ""
              passwordGeneratorModalComponent.generatedEntropy = (typeof data.entropy === "number") ? data.entropy : passwordGeneratorModalComponent.calculateEntropy()
            } else if (data && data.error) {
              passwordGeneratorModalComponent.errorMessage = data.error
              passwordGeneratorModalComponent.generatedPassword = ""
            }
          } catch (e) {
            passwordGeneratorModalComponent.errorMessage = ""
            passwordGeneratorModalComponent.generatedPassword = out
            passwordGeneratorModalComponent.generatedEntropy = passwordGeneratorModalComponent.calculateEntropy()
          }
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.handleProcessStderr(text, "omawarden:generate")
        if (!passwordGeneratorModalComponent) return
        passwordGeneratorModalComponent.isGenerating = false
        var err = (text || "").trim()
        if (err) {
          err = err.replace(/^Error:\s*/i, "")
          if (/unrecognized subcommand|not a recognized subcommand/i.test(err)) {
            var currentVer = (root.cliHealth && root.cliHealth.version) ? (" (v" + root.cliHealth.version + ")") : ""
            err = "omawarden engine is outdated" + currentVer + ". Please upgrade omawarden to >= " + root.minimumGeneratorEngineVersion + " to support credential generation."
          }
          if (!passwordGeneratorModalComponent.errorMessage) {
            passwordGeneratorModalComponent.errorMessage = err
            passwordGeneratorModalComponent.generatedPassword = ""
          }
        }
      }
    }
    onExited: function(exitCode) {
      if (passwordGenProc.isCanceled) {
        passwordGenProc.isCanceled = false
        return
      }
      if (!passwordGeneratorModalComponent) return
      passwordGeneratorModalComponent.isGenerating = false
      if (exitCode !== 0 && !passwordGeneratorModalComponent.errorMessage) {
        passwordGeneratorModalComponent.errorMessage = "Process exited with error code " + exitCode
        passwordGeneratorModalComponent.generatedPassword = ""
      }
    }
  }

  function generatePasswordOrPassphrase(options) {
    if (!passwordGeneratorModalComponent) return
    var cliVer = (root.cliHealth && root.cliHealth.version) ? root.cliHealth.version : ""
    if (cliVer && root.compareSemVer(cliVer, root.minimumGeneratorEngineVersion) < 0) {
      passwordGeneratorModalComponent.isGenerating = false
      passwordGeneratorModalComponent.generatedPassword = ""
      passwordGeneratorModalComponent.errorMessage = "omawarden engine is outdated (v" + cliVer + "). Please upgrade omawarden to >= " + root.minimumGeneratorEngineVersion + " to support credential generation."
      return
    }
    passwordGeneratorModalComponent.errorMessage = ""
    passwordGeneratorModalComponent.isGenerating = true
    if (passwordGenProc.running) {
      passwordGenProc.isCanceled = true
      passwordGenProc.running = false
    }
    var cmd = [root.helperPath, "generate", "--json"]
    if (options && options.mode === "passphrase") {
      cmd.push("--passphrase")
      cmd.push("-w", String(options.words || 4))
      cmd.push("-s", options.separator || "-")
      if (options.capitalize) cmd.push("--capitalize")
    } else {
      cmd.push("-l", String((options && options.length) || 20))
      if (options && !options.uppercase) cmd.push("--no-uppercase")
      if (options && !options.lowercase) cmd.push("--no-lowercase")
      if (options && !options.numbers) cmd.push("--no-numbers")
      if (options && !options.special) cmd.push("--no-special")
      if (options && options.avoidAmbiguous) cmd.push("--avoid-ambiguous")
    }
    passwordGenProc.command = cmd
    passwordGenProc.running = true
  }

  Process {
    id: configGetProc
    property int seq: 0
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (configGetProc.seq !== root.configSeq) return
        try {
          var cleanText = (text || "").trim()
          if (cleanText.length === 0) return
          var data = JSON.parse(cleanText)
          root.config = data
          if (data.remember_email !== undefined) {
            root.rememberEmailChecked = (data.remember_email !== false)
          }
        } catch (e) {
          root.logError("omarchy:ui", "Failed to parse config: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:config")
    }
  }

  Process {
    id: configSetProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        try {
          var cleanSetText = (text || "").trim()
          if (cleanSetText.length === 0) return
          var data = JSON.parse(cleanSetText)
          root.config = data
          root.statusMessage = "Configuration saved successfully."
          root.refreshHealth()
          root.refreshAuthStatus()
        } catch (e) {
          root.statusMessage = "Failed to update config."
          root.logError("omarchy:ui", "Failed to parse updated config: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:config")
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0) root.statusMessage = "Error saving configuration."
    }
  }

  Process {
    id: healthProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var cleanText = (text || "").trim()
          if (cleanText.length === 0) {
            root.cliHealth = ({
              installed: false,
              ok: false,
              version: "",
              server_reachable: false,
              keyring_available: false,
              clipboard_available: false,
              error: "CLI executable not found or output empty."
            })
            return
          }
          var data = JSON.parse(cleanText)
          if (data && typeof data === "object") {
            if (data.installed && data.version && !root.isEngineVersionSatisfied(data.version)) {
              data.ok = false
              data.error = "omawarden engine is outdated (v" + data.version + "). Minimum version required: >= " + root.minimumEngineVersion + "."
            }
            root.cliHealth = data
          }
        } catch (e) {
          root.cliHealth = ({
            installed: false,
            ok: false,
            version: "",
            server_reachable: false,
            keyring_available: false,
            clipboard_available: false,
            error: "Failed to parse CLI health output."
          })
          root.logError("omarchy:ui", "Failed to parse health status: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:health")
    }
    onExited: function(code) {
      if (code !== 0) {
        root.cliHealth = ({
          installed: false,
          ok: false,
          version: "",
          server_reachable: false,
          keyring_available: false,
          clipboard_available: false,
          error: "CLI executable not found or failed to execute."
        })
      }
    }
  }


  Process {
    id: quickUnlockCheckProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse((text || "").trim())
          root.quickUnlockReady = Boolean(data && data.available)
        } catch (e) {
          // Older engines have no quick-unlock subcommand: fail closed.
          root.quickUnlockReady = false
        }
      }
    }
    onExited: function(code) {
      if (code !== 0) root.quickUnlockReady = false
    }
  }

  Process {
    id: authStatusProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var cleanText = (text || "").trim()
          if (cleanText.length === 0) return
          var data = JSON.parse(cleanText)
          if (data && data.status) {
            var wasNotUnlocked = (root.authState.status !== "unlocked")
            root.authState = data
            if (data.status === "unlocked") {
              if (wasNotUnlocked || !root.rawVaultItems || root.rawVaultItems.length === 0) {
                root.loadVaultItems()
                root.syncVault(true, false)
              }
            } else {
              root.clearSensitiveState()
              // A lock just landed (screen lock, idle timeout, suspend or the
              // 12h ceiling). The polling path above skips readiness while
              // unlocked and lockSyncTimer stops once locked, so this is the
              // only place that can show or hide the quick unlock button on
              // the transition.
              root.refreshQuickUnlockAvailability()
            }
            Qt.callLater(function() {
              if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.hasActiveModal) {
                if (!searchHeader.searchField.activeFocus) {
                  var canRemember = Boolean(root.config && root.config.remember_last_search === true && root.authState && root.authState.status === "unlocked")
                  searchHeader.focusSearch(canRemember)
                }
              }
            })
          }
        } catch (e) {
          root.clearSensitiveState()
          root.authState = ({
            status: "unauthenticated",
            server_url: "",
            user_email: "",
            has_session: false
          })
          root.logError("omarchy:auth", "Failed to parse auth status: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
    }
    onExited: function(code) {
      if (code !== 0) {
        root.clearSensitiveState()
        root.authState = ({
          status: "unauthenticated",
          server_url: "",
          user_email: "",
          has_session: false
        })
      }
    }
  }

  Process {
    id: authUnlockProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            root.statusMessage = "Vault unlocked successfully."
            root.searchQuery = ""
            if (authViewComponent) authViewComponent.clearInputs()
            root.authState = ({
              status: "unlocked",
              server_url: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "",
              user_email: (root.authState && root.authState.user_email) || (root.config && root.config.email) || "",
              has_session: true
            })
            root.refreshAuthStatus()
            root.loadVaultItems()
            root.syncVault(true, true)
          } else {
            root.errorMessage = data.error || "Unlock failed."
            root.logWarn("omarchy:auth", root.errorMessage)
            // Denied quick unlocks may have wiped the retained key.
            root.refreshQuickUnlockAvailability()
          }
        } catch (e) {
          root.errorMessage = "Failed to parse unlock response."
          root.logError("omarchy:auth", root.errorMessage + ": " + e)
        }
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0 && !root.errorMessage) root.errorMessage = "Unlock command failed."
    }
  }

  Process {
    id: authLoginProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            var statusVal = data.status || "unlocked"
            if (statusVal === "locked") {
              root.statusMessage = "API Key authenticated. Please enter Master Password to unlock."
            } else {
              root.statusMessage = "Logged in successfully."
            }
            root.searchQuery = ""
            root.show2FAField = false
            root.isNewDeviceVerification = false
            root.twoFactorProvider = 0
            root.availableTwoFactorProviders = []
            root.fido2Status = ""
            if (authViewComponent) {
              authViewComponent.clearInputs()
              authViewComponent.show2FAField = false
              authViewComponent.isNewDeviceVerification = false
              authViewComponent.twoFactorProvider = 0
              authViewComponent.availableTwoFactorProviders = []
              authViewComponent.fido2Status = ""
            }
            root.authState = ({
              status: statusVal,
              server_url: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "",
              user_email: (root.authState && root.authState.user_email) || (root.config && root.config.email) || "",
              has_session: true
            })
            root.refreshAuthStatus()
            root.refreshConfig()
            if (statusVal === "unlocked") {
              root.loadVaultItems()
              root.syncVault(true, true)
            }
          } else {
            var errLower = (data.error || "").toLowerCase()
            var isNewDevice = Boolean(data.new_device_verification_required)
                || errLower.indexOf("new device verification") !== -1
            var is2FA = isNewDevice
                || Boolean(data.two_factor_required)
                || errLower.indexOf("two-step") !== -1
                || errLower.indexOf("two-factor") !== -1
                || errLower.indexOf("two factor") !== -1
                || errLower.indexOf("twofactor") !== -1
                || errLower.indexOf("2fa") !== -1
                || errLower.indexOf("verification code") !== -1
                || errLower.indexOf("authenticator code") !== -1
                || errLower.indexOf("security code") !== -1
                || errLower.indexOf("security key") !== -1
                || errLower.indexOf("webauthn") !== -1
            var was2FAShown = root.show2FAField
            if (is2FA && !was2FAShown) {
              root.errorMessage = ""
              root.statusMessage = ""
              root.logInfo("omarchy:auth", "Two-factor authentication required for login.")
            } else {
              root.errorMessage = data.error || "Login failed."
              root.logWarn("omarchy:auth", root.errorMessage)
            }
            root.isNewDeviceVerification = isNewDevice
            var prov = (data.two_factor_provider !== undefined && data.two_factor_provider !== null)
                ? Number(data.two_factor_provider)
                : 0
            if (data.two_factor_providers && data.two_factor_providers.length > 0) {
              root.availableTwoFactorProviders = data.two_factor_providers
              if (data.two_factor_provider === undefined || data.two_factor_provider === null) {
                if (data.two_factor_providers.indexOf(7) !== -1) {
                  prov = 7
                } else if (data.two_factor_providers.indexOf(0) !== -1) {
                  prov = 0
                } else if (data.two_factor_providers.indexOf(1) !== -1) {
                  prov = 1
                }
              }
            } else {
              root.availableTwoFactorProviders = []
            }
            root.twoFactorProvider = prov
            root.fido2Status = data.fido2_status || ""
            if (is2FA) {
              root.show2FAField = true
              if (prov !== 7 && authViewComponent && authViewComponent.twoFactorInput) {
                Qt.callLater(function() {
                  authViewComponent.twoFactorInput.forceActiveFocus()
                })
              }
            } else {
              root.show2FAField = false
            }
            if (authViewComponent) {
              authViewComponent.show2FAField = root.show2FAField
              authViewComponent.isNewDeviceVerification = root.isNewDeviceVerification
              authViewComponent.twoFactorProvider = root.twoFactorProvider
              authViewComponent.availableTwoFactorProviders = root.availableTwoFactorProviders
              authViewComponent.fido2Status = root.fido2Status
            }
          }
        } catch (e) {
          root.errorMessage = "Failed to parse login response."
          root.logError("omarchy:auth", root.errorMessage + ": " + e)
        }
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0 && !root.errorMessage && !root.show2FAField) root.errorMessage = "Login command failed."
    }
  }

  Process {
    id: authSendEmailProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            root.statusMessage = data.message || "Verification code sent to your email."
            if (authViewComponent) {
              authViewComponent.notifyEmailCodeSent()
            }
          } else {
            root.errorMessage = data.error || "Failed to send verification email."
            root.logWarn("omarchy:auth", root.errorMessage)
            if (authViewComponent) {
              authViewComponent.notifyEmailCodeFailed()
            }
          }
        } catch (e) {
          root.errorMessage = "Failed to parse send email response."
          root.logError("omarchy:auth", root.errorMessage + ": " + e)
          if (authViewComponent) {
            authViewComponent.notifyEmailCodeFailed()
          }
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0 && !root.errorMessage) {
        root.errorMessage = "Failed to send verification email."
        if (authViewComponent) {
          authViewComponent.notifyEmailCodeFailed()
        }
      }
    }
  }

  Process {
    id: authFido2CheckProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (data.ok && data.status) {
            root.fido2Status = data.status
            if (authViewComponent) {
              authViewComponent.fido2Status = data.status
            }
          }
        } catch (e) {}
      }
    }
  }

  Process {
    id: authLockProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.clearSensitiveState()
        root.authState = ({
          status: "locked",
          server_url: (root.authState && root.authState.server_url) || "",
          user_email: (root.authState && root.authState.user_email) || "",
          has_session: Boolean(root.authState && root.authState.has_session)
        })
        root.refreshAuthStatus()
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
    }
    onExited: function(code) {
      root.isBusy = false
    }
  }

  Process {
    id: authLogoutProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.clearSensitiveState()
        root.authState = ({
          status: "unauthenticated",
          server_url: (root.config && root.config.server_url) || "",
          user_email: "",
          has_session: false
        })
        root.refreshAuthStatus()
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
    }
    onExited: function(code) {
      root.isBusy = false
    }
  }

  Process {
    id: vaultSyncProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        try {
          var res = JSON.parse(text)
          if (res && res.ok === false) {
            var rawError = String(res.error || "Vault sync failed.")
            root.logError("omarchy:vault", "Vault sync failed: " + rawError)
            root.errorMessage = root.formatSyncError(rawError)
            var errStr = rawError
            if (errStr.indexOf("Session expired") !== -1 || errStr.indexOf("Please log in") !== -1 || errStr.indexOf("token missing") !== -1) {
              root.clearSensitiveState()
              root.authState = ({
                status: "unauthenticated",
                server_url: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "",
                user_email: (root.authState && root.authState.user_email) || (root.config && root.config.email) || "",
                has_session: false
              })
              root.currentView = "auto"
            }
            return
          }
        } catch (e) {
          // Non-JSON output
        }
        if (!root.authState || root.authState.status !== "unlocked") {
          root.clearSensitiveState()
          return
        }
        root.lastSyncTime = Date.now()
        root.statusMessage = "Vault synchronized."
        root.loadVaultItems()
        Qt.callLater(function() {
          if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.hasActiveModal) {
            searchHeader.searchField.forceActiveFocus()
          }
        })
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:vault")
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0 && !root.errorMessage) {
        root.errorMessage = "Vault sync failed."
        root.logError("omarchy:vault", "Vault sync process exited with code " + code)
      }
    }
  }

  Process {
    id: vaultListProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          root.isLoadingVault = false
          if (!root.authState || root.authState.status !== "unlocked") {
            root.clearSensitiveState()
            return
          }
          var cleanText = (text || "").trim()
          if (cleanText === root.lastVaultItemsRawText && root.rawVaultItems && root.rawVaultItems.length > 0) {
            Qt.callLater(function() {
              if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.hasActiveModal) {
                searchHeader.searchField.forceActiveFocus()
              }
            })
            return
          }
          root.applyVaultListing(JSON.parse(cleanText), cleanText)
          root.filterVaultItems(false)
          Qt.callLater(function() {
            if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.hasActiveModal) {
              searchHeader.searchField.forceActiveFocus()
            }
          })
        } catch (e) {
          root.logError("omarchy:vault", "Failed to parse vault items: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:vault")
    }
  }

  Process {
    id: clipCopyProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
    command: []
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:clipboard")
    }
  }

  // Per-field secret release (contracts.md section 3). Active only while the
  // overlay shows the unlocked vault; inactive drops every revealed value.
  SecretReleaseController {
    id: secretRelease
    helperPath: root.helperPath
    active: root.opened && Boolean(root.authState && root.authState.status === "unlocked") && root.effectiveView === "search"
    itemId: root.selectedItem ? String(root.selectedItem.id || "") : ""
    clipboardClearSeconds: root.clipboardClearSeconds()
    // Requested only after the previous release process has exited.
    onCommandRequested: function(argv) {
      secretFieldProc.command = argv
      secretFieldProc.running = true
    }
    onCommandStopRequested: function(forceful) { root.stopSecretFieldProcess(forceful) }
    onCopyConfirmed: function(label, clearSeconds) { root.confirmSecretCopy(label, clearSeconds) }
    onReleaseRefused: function(errorCode, message) { root.handleReleaseRefusal(errorCode, message) }
    onPasswordHistoryConcealed: root.showPasswordHistoryModal = false
  }

  readonly property int forcefulStopSignal: 9 // SIGKILL

  // A release that timed out: stopping the process (SIGTERM) comes first; a
  // process that still has not exited is killed.
  function stopSecretFieldProcess(forceful) {
    if (forceful) secretFieldProc.signal(root.forcefulStopSignal)
    else secretFieldProc.running = false
  }

  // Runs `vault reveal` / `vault copy-field`. argv holds only the item id and
  // the field identifier; stdout carries the JSON envelope and is handed to
  // the controller without being logged.
  Process {
    id: secretFieldProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: secretRelease.handleCommandOutput(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:secrets")
    }
    onExited: function(exitCode) { secretRelease.handleCommandExit(exitCode) }
  }
}
