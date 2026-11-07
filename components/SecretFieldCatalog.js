.pragma library

// Field identifiers, presence flags and response parsing for the per-field
// secret release contract (docs/agents/contracts.md section 3). Redacted
// items carry `has_*` flags instead of secrets; a secret is released one
// field at a time with `omawarden vault reveal` / `vault copy-field`, whose
// argv carries only the item id and the field identifier.

var LOGIN_PASSWORD = "login.password"
var LOGIN_TOTP = "login.totp"
var NOTES = "notes"
var CARD_NUMBER = "card.number"
var CARD_CODE = "card.code"
var IDENTITY_SSN = "identity.ssn"
var IDENTITY_PASSPORT_NUMBER = "identity.passport_number"
var IDENTITY_LICENSE_NUMBER = "identity.license_number"
var PASSWORD_HISTORY = "password_history"
var CUSTOM_FIELD_PREFIX = "custom."

var CUSTOM_FIELD_TYPE_TEXT = 0
var CUSTOM_FIELD_TYPE_HIDDEN = 1
var CUSTOM_FIELD_TYPE_BOOLEAN = 2

// Accepted range of `--clear-after` (contracts.md 3.4).
var CLEAR_AFTER_MINIMUM_SECONDS = 1
var CLEAR_AFTER_MAXIMUM_SECONDS = 3600

// Field identifier -> [section of the redacted item ("" for the top level),
// presence flag in that section].
var PRESENCE_FLAGS = {
  "login.password": ["login", "has_password"],
  "login.totp": ["login", "has_totp"],
  "password_history": ["login", "has_password_history"],
  "notes": ["", "has_notes"],
  "card.number": ["card", "has_number"],
  "card.code": ["card", "has_code"],
  "identity.ssn": ["identity", "has_ssn"],
  "identity.passport_number": ["identity", "has_passport_number"],
  "identity.license_number": ["identity", "has_license_number"]
}

// Secrets tried in order for the primary action (Enter) and the reveal
// shortcut (Ctrl+T) of each item type.
var PRIMARY_SECRET_CANDIDATES = {
  "login": [LOGIN_PASSWORD, NOTES],
  "card": [CARD_NUMBER, CARD_CODE, NOTES],
  "identity": [IDENTITY_SSN, IDENTITY_PASSPORT_NUMBER, IDENTITY_LICENSE_NUMBER, NOTES],
  "note": [NOTES]
}

// Wording used in copy confirmations ("Copied <label> to the clipboard").
var FIELD_LABELS = {
  "login.password": "password",
  "login.totp": "TOTP code",
  "notes": "notes",
  "card.number": "card number",
  "card.code": "security code",
  "identity.ssn": "social security number",
  "identity.passport_number": "passport number",
  "identity.license_number": "license number",
  "password_history": "password history"
}

// error_code -> i18n key of the message shown to the user.
var ERROR_MESSAGE_KEYS = {
  "release_limit_exceeded": "error.release_limit_exceeded",
  "vault_locked": "error.vault_locked",
  "item_not_found": "error.item_not_found",
  "field_empty": "error.field_empty",
  "unknown_field": "error.unknown_field",
  "field_not_copyable": "error.field_not_copyable",
  "clipboard_failed": "error.clipboard_failed",
  "invalid_request": "error.invalid_request"
}

// Error codes after which the daemon is locked, so the overlay must return
// to the unlock view.
var VAULT_LOCKING_ERROR_CODES = {
  "release_limit_exceeded": true,
  "vault_locked": true
}

// Values a redacted item never carries (contracts.md 3.2), as [section of
// the item ("" for the top level), key], in the spellings of the redacted
// contract, of Bitwarden and of the engine's decrypted model.
var SECRET_VALUE_PATHS = [
  ["", "notes"], ["", "search_text"], ["", "passwordHistory"], ["", "password_history"],
  ["login", "password"], ["login", "totp"], ["login", "passwordHistory"], ["login", "password_history"],
  ["card", "number"], ["card", "code"],
  ["identity", "ssn"], ["identity", "passportNumber"], ["identity", "licenseNumber"],
  ["identity", "passport_number"], ["identity", "license_number"]
]

// What a `vault list` reply is (see classifyVaultListing).
var LISTING_REDACTED = "redacted"
var LISTING_UNREDACTED = "unredacted"
var LISTING_NOT_A_LISTING = "not_a_listing"

function customFieldIdentifier(index) {
  return CUSTOM_FIELD_PREFIX + index
}

function isCustomFieldIdentifier(field) {
  return String(field || "").indexOf(CUSTOM_FIELD_PREFIX) === 0
}

function customFieldByIdentifier(item, field) {
  if (!item || !Array.isArray(item.fields) || !isCustomFieldIdentifier(field)) return null
  var index = Number(String(field).substring(CUSTOM_FIELD_PREFIX.length))
  for (var i = 0; i < item.fields.length; i++) {
    if (item.fields[i] && item.fields[i].index === index) return item.fields[i]
  }
  return null
}

function presenceFlag(item, section, flag) {
  var holder = section ? item[section] : item
  return Boolean(holder && holder[flag] === true)
}

// Whether the redacted item says a value exists for this field.
function isPresent(item, field) {
  if (!item) return false
  var flag = PRESENCE_FLAGS[field]
  if (flag) return presenceFlag(item, flag[0], flag[1])
  var custom = customFieldByIdentifier(item, field)
  return Boolean(custom && custom.has_value === true)
}

function customFieldsWithValue(item) {
  if (!item || !Array.isArray(item.fields)) return []
  return item.fields.filter(function(field) {
    return Boolean(field && field.has_value === true)
  })
}

function isHiddenCustomField(field) {
  return Boolean(field) && field.type === CUSTOM_FIELD_TYPE_HIDDEN
}

// Text and boolean custom fields carry their value in the redacted item.
function hasPublicCustomValue(field) {
  return Boolean(field) && (field.type === CUSTOM_FIELD_TYPE_TEXT || field.type === CUSTOM_FIELD_TYPE_BOOLEAN)
}

function isSecretValue(value) {
  if (value === undefined || value === null || value === "") return false
  return !Array.isArray(value) || value.length > 0
}

function sectionValue(item, section, key) {
  var holder = section ? item[section] : item
  return (holder && typeof holder === "object") ? holder[key] : undefined
}

// A hidden, linked or unknown custom field carries no value when redacted.
function carriesSecretCustomValue(field) {
  return Boolean(field) && !hasPublicCustomValue(field) && isSecretValue(field.value)
}

function itemCarriesSecretValue(item) {
  if (!item || typeof item !== "object") return false
  var inSections = SECRET_VALUE_PATHS.some(function(path) {
    return isSecretValue(sectionValue(item, path[0], path[1]))
  })
  return inSections || (Array.isArray(item.fields) && item.fields.some(carriesSecretCustomValue))
}

// LISTING_REDACTED for an array of redacted items; LISTING_UNREDACTED when any
// item carries a secret value, which only an engine that does not redact
// sends (the whole listing must then be discarded); LISTING_NOT_A_LISTING for
// anything else, such as the error envelope of a locked daemon.
function classifyVaultListing(listing) {
  if (!Array.isArray(listing)) return LISTING_NOT_A_LISTING
  return listing.some(itemCarriesSecretValue) ? LISTING_UNREDACTED : LISTING_REDACTED
}

// The secret Enter copies and Ctrl+T reveals for this item, or "".
function primarySecretField(item) {
  if (!item) return ""
  var candidates = PRIMARY_SECRET_CANDIDATES[item.type_name] || [NOTES]
  for (var i = 0; i < candidates.length; i++) {
    if (isPresent(item, candidates[i])) return candidates[i]
  }
  var custom = customFieldsWithValue(item)
  return custom.length > 0 ? customFieldIdentifier(custom[0].index) : ""
}

function fieldLabel(item, field) {
  if (FIELD_LABELS[field]) return FIELD_LABELS[field]
  var custom = customFieldByIdentifier(item, field)
  return (custom && custom.name) ? String(custom.name) : "field value"
}

function errorMessageKey(code) {
  return ERROR_MESSAGE_KEYS[code] || ""
}

function errorLocksVault(code) {
  return VAULT_LOCKING_ERROR_CODES[code] === true
}

function isValidClearAfter(seconds) {
  return Number.isInteger(seconds) && seconds >= CLEAR_AFTER_MINIMUM_SECONDS && seconds <= CLEAR_AFTER_MAXIMUM_SECONDS
}

// `--id=<id>` keeps an id that starts with "-" from being read as an option.
function revealArguments(helperPath, itemId, field) {
  return [helperPath, "vault", "reveal", "--id=" + itemId, "--field=" + field]
}

function copyArguments(helperPath, itemId, field, clearAfterSeconds) {
  var argv = [helperPath, "vault", "copy-field", "--id=" + itemId, "--field=" + field]
  if (isValidClearAfter(clearAfterSeconds)) argv.push("--clear-after=" + clearAfterSeconds)
  return argv
}

function failure(code, message) {
  return { ok: false, errorCode: code || "", error: message || "" }
}

function parseJson(text) {
  try {
    var parsed = JSON.parse(text)
    return (parsed && typeof parsed === "object") ? parsed : null
  } catch (e) {
    return null
  }
}

function normalizeHistory(value) {
  if (!Array.isArray(value)) return []
  return value.map(function(entry) {
    return {
      password: (entry && entry.password !== undefined && entry.password !== null) ? String(entry.password) : "",
      last_used_date: (entry && entry.last_used_date) ? String(entry.last_used_date) : ""
    }
  })
}

function releasedValue(data) {
  return data.field === PASSWORD_HISTORY ? normalizeHistory(data.value) : String(data.value)
}

function successResponse(data) {
  return {
    ok: true,
    id: String(data.id || ""),
    field: String(data.field || ""),
    value: data.value === undefined ? undefined : releasedValue(data),
    secondsRemaining: Number(data.seconds_remaining) || 0,
    period: Number(data.period) || 0,
    clearAfterSeconds: Number(data.clear_after_seconds) || 0
  }
}

// Parses the JSON envelope of `vault reveal` / `vault copy-field`. A missing
// or unparsable envelope is a failure without an error code.
function parseReleaseResponse(text, exitCode) {
  var data = parseJson(String(text || "").trim())
  if (!data) return failure("", exitCode === 0 ? "" : ("omawarden exited with code " + exitCode))
  if (data.ok !== true) return failure(data.error_code, data.error)
  return successResponse(data)
}
