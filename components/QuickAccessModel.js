.pragma library
.import "VaultSearch.js" as VaultSearch
.import "SecretFieldCatalog.js" as SecretFieldCatalog

// State and ranking for the bar dropdown (quick access panel). The dropdown
// lists redacted login items only; secrets are copied by the daemon through
// `vault copy-field`, and usernames, which are public fields of a redacted
// item, through `copy --stdin`.

var VIEW_LOADING = "loading"
var VIEW_ENGINE_UNAVAILABLE = "engine_unavailable"
var VIEW_SIGNED_OUT = "signed_out"
var VIEW_LOCKED = "locked"
var VIEW_UNLOCKED = "unlocked"

var COPY_USERNAME = "username"
var COPY_PASSWORD = "password"
var COPY_TOTP = "totp"
var COPY_SEQUENCE = "sequence"

// Copy kind -> field identifier of `vault copy-field` ("" for the username,
// which is not a secret and is copied from the listing).
var SECRET_FIELDS = {
  "username": "",
  "password": SecretFieldCatalog.LOGIN_PASSWORD,
  "totp": SecretFieldCatalog.LOGIN_TOTP
}

// Wording of the copy confirmation for each copy kind.
var COPY_LABELS = {
  "username": "Username",
  "password": "Password",
  "totp": "Verification code"
}

// Fields of the paste sequence, in paste order: the first paste yields the
// password and the next paste the current verification code (for sign-in
// prompts such as Teleport's that ask for both, one after the other).
var PASTE_SEQUENCE_FIELDS = [SecretFieldCatalog.LOGIN_PASSWORD, SecretFieldCatalog.LOGIN_TOTP]

function parseJson(text) {
  try {
    var parsed = JSON.parse(String(text || "").trim())
    return (parsed && typeof parsed === "object") ? parsed : null
  } catch (e) {
    return null
  }
}

// View for the reply of `auth status`. A reply that is not a status object
// means the engine could not be run or answered with something unexpected;
// the exit status is not consulted, since the status object is the answer.
function viewForAuthStatus(text) {
  var status = parseJson(text)
  if (!status || typeof status.status !== "string") return VIEW_ENGINE_UNAVAILABLE
  if (status.status === "unlocked") return VIEW_UNLOCKED
  if (status.status === "locked" && status.has_session === true) return VIEW_LOCKED
  return VIEW_SIGNED_OUT
}

function usernameOf(item) {
  var login = item ? item.login : null
  return (login && typeof login.username === "string") ? login.username : ""
}

function canCopy(item, kind) {
  if (!item) return false
  if (kind === COPY_USERNAME) return usernameOf(item) !== ""
  var field = SECRET_FIELDS[kind]
  return Boolean(field) && SecretFieldCatalog.isPresent(item, field)
}

function canCopySequence(item) {
  return canCopy(item, COPY_PASSWORD) && canCopy(item, COPY_TOTP)
}

// argv of `vault copy-sequence`: only the item id and the field identifiers.
// `--id=<id>` keeps an id that starts with "-" from being read as an option.
function sequenceArguments(itemId) {
  return ["vault", "copy-sequence", "--id=" + itemId, "--fields=" + PASTE_SEQUENCE_FIELDS.join(",")]
}

// First website of a login item, for display only.
function websiteOf(item) {
  var uris = (item && item.login && Array.isArray(item.login.uris)) ? item.login.uris : []
  for (var i = 0; i < uris.length; i++) {
    var entry = uris[i]
    var uri = (entry && typeof entry === "object") ? entry.uri : entry
    if (typeof uri === "string" && uri !== "") return uri
  }
  return ""
}

function isQuickAccessItem(item) {
  return Boolean(item) && item.type_name === "login"
    && (canCopy(item, COPY_USERNAME) || canCopy(item, COPY_PASSWORD) || canCopy(item, COPY_TOTP))
}

function compareByFavoriteThenName(a, b) {
  if (Boolean(a.favorite) !== Boolean(b.favorite)) return a.favorite ? -1 : 1
  return String(a.name || "").localeCompare(String(b.name || ""), undefined, { sensitivity: "base" })
}

// Recent logins shown above the others while no query is typed.
var RECENT_LIMIT = 5

function compareByUsage(a, b) {
  return VaultSearch.usageScore(b) - VaultSearch.usageScore(a)
}

// Up to RECENT_LIMIT recent logins, most used first.
function recentLogins(logins) {
  return logins.filter(VaultSearch.isRecent).sort(compareByUsage).slice(0, RECENT_LIMIT)
}

// Login items for the query. With no query: the recent logins first, then
// every other login, favourites first and then by name. With a query: the
// ranking of the full overlay, in which recent use orders equal matches.
function rankItems(items, query) {
  var logins = (Array.isArray(items) ? items : []).filter(isQuickAccessItem)
  if (VaultSearch.queryWords(query).length > 0) return VaultSearch.filterItems(logins, query, { category: "login" })
  var recent = recentLogins(logins)
  var others = logins.filter(function(item) { return recent.indexOf(item) === -1 }).sort(compareByFavoriteThenName)
  return recent.concat(others)
}

// How many of the leading items of a ranking are the recent section: none
// while a query is typed.
function recentCount(ranked, query) {
  if (VaultSearch.queryWords(query).length > 0) return 0
  var count = 0
  while (count < ranked.length && count < RECENT_LIMIT && VaultSearch.isRecent(ranked[count])) count++
  return count
}

// Copy Enter performs: the password, else the username, else the code.
function primaryCopyKind(item) {
  var order = [COPY_PASSWORD, COPY_USERNAME, COPY_TOTP]
  for (var i = 0; i < order.length; i++) {
    if (canCopy(item, order[i])) return order[i]
  }
  return ""
}

function secretField(kind) {
  return SECRET_FIELDS[kind] || ""
}

function copyLabel(kind) {
  return COPY_LABELS[kind] || "Value"
}

// Confirmation shown on the details page after a copy.
function copyConfirmation(kind, clearAfterSeconds) {
  var sentence = copyLabel(kind) + " copied."
  return clearAfterSeconds > 0 ? sentence + " The clipboard clears in " + clearAfterSeconds + " s." : sentence
}

// Listing reply of `vault list`: the redacted items, or null when the reply
// is not a redacted listing (a locked daemon's error envelope, or an engine
// that sends secrets, whose listing is discarded whole).
function redactedListing(text) {
  var listing = parseJson(text)
  return SecretFieldCatalog.classifyVaultListing(listing) === SecretFieldCatalog.LISTING_REDACTED ? listing : null
}

function clampIndex(index, count) {
  if (count <= 0) return -1
  return Math.max(0, Math.min(count - 1, index))
}
