.pragma library

// Which item URIs may be handed to Qt.openUrlExternally. Only http:// and
// https:// open; every other scheme (file://, smb://, ssh://, custom
// application schemes) is shown and copyable but never opened, because the
// desktop would dispatch it to whatever handler claims the scheme. A value
// without a scheme ("github.com/login", "localhost:8080") is opened as https.

var OPENABLE_SCHEME_PATTERN = /^https?:\/\/[^\s]+$/i
var SCHEME_PATTERN = /^[a-z][a-z0-9+.\-]*:/i
// A leading `host:port` looks like `scheme:` but is a schemeless address: a
// host name or IPv4 address of DNS labels, a colon and a decimal port, then
// the end or a path, query or fragment ("github.com:443/x").
var HOST_PORT_PATTERN = /^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*:([0-9]{1,5})(?:[\/?#]|$)/i
var MINIMUM_PORT = 1
var MAXIMUM_PORT = 65535
// Control characters and whitespace never belong in a URL we open.
var UNSAFE_CHARACTER_PATTERN = /[\u0000- \u007f]/

var KIND_WEBSITE = "website"
var KIND_OTHER = "other"

function isSchemelessHostPort(uri) {
  var match = HOST_PORT_PATTERN.exec(uri)
  if (!match) return false
  var port = Number(match[1])
  return port >= MINIMUM_PORT && port <= MAXIMUM_PORT
}

// The result is always opened as https, so a scheme mistaken for a host
// (`mailto:25`) can only ever become an https URL.
function hasScheme(uri) {
  return SCHEME_PATTERN.test(uri) && !isSchemelessHostPort(uri)
}

// The URL to open for a stored URI, or "" when it must not be opened.
function openableUrl(uri) {
  var text = String(uri === undefined || uri === null ? "" : uri).trim()
  if (!text || UNSAFE_CHARACTER_PATTERN.test(text)) return ""
  var candidate = hasScheme(text) ? text : ("https://" + text)
  return OPENABLE_SCHEME_PATTERN.test(candidate) ? candidate : ""
}

function isOpenable(uri) {
  return openableUrl(uri) !== ""
}

function rawUriOf(entry) {
  if (typeof entry === "string") return entry
  return (entry && entry.uri) ? String(entry.uri) : ""
}

function describeUri(raw) {
  var openUrl = openableUrl(raw)
  return {
    uri: raw,
    openUrl: openUrl,
    isOpenable: openUrl !== "",
    kind: openUrl !== "" ? KIND_WEBSITE : KIND_OTHER
  }
}

// The login URIs of an item, trimmed and de-duplicated, openable ones first.
// Each entry keeps the full URI for display and copying.
function itemUris(item) {
  var stored = (item && item.login && Array.isArray(item.login.uris)) ? item.login.uris : []
  var seen = {}
  var entries = []
  for (var i = 0; i < stored.length; i++) {
    var raw = rawUriOf(stored[i]).trim()
    if (!raw || seen[raw]) continue
    seen[raw] = true
    entries.push(describeUri(raw))
  }
  var openable = entries.filter(function(entry) { return entry.isOpenable })
  var other = entries.filter(function(entry) { return !entry.isOpenable })
  return openable.concat(other)
}

function firstOpenableUrl(item) {
  var entries = itemUris(item)
  return (entries.length > 0 && entries[0].isOpenable) ? entries[0].openUrl : ""
}
