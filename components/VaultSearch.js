.pragma library

// Local filtering and ranking of redacted vault items. Redacted items carry
// no secrets and no engine search text, so the searchable text is built here
// from the public fields only (contracts.md 3.2): usernames, URIs, card
// brand / holder / last four digits, identity contact fields, folder and
// organization names, and custom field names with their public values.

var FAVORITE_SCORE = 100
var NO_MATCH = -1

// Ranked matchers for one query word, strongest first.
var WORD_MATCHERS = [
  { score: 2000, matches: function(word, text) { return text.name === word } },
  { score: 1000, matches: function(word, text) { return text.name.indexOf(word) === 0 } },
  { score: 500, matches: function(word, text) { return text.name.indexOf(word) !== -1 } },
  { score: 400, matches: function(word, text) { return text.subtitle.indexOf(word) === 0 } },
  { score: 300, matches: function(word, text) { return text.subtitle.indexOf(word) !== -1 } },
  { score: 100, matches: function(word, text) { return text.searchable.indexOf(word) !== -1 } },
  { score: 80, matches: function(word, text) { return isSubsequence(word, text.name) } }
]

function isSubsequence(pattern, text) {
  if (!pattern) return true
  var position = 0
  for (var i = 0; i < text.length && position < pattern.length; i++) {
    if (text[i] === pattern[position]) position++
  }
  return position === pattern.length
}

function lower(value) {
  return (value === undefined || value === null) ? "" : String(value).toLowerCase()
}

function sectionValues(section, keys) {
  if (!section) return []
  return keys.map(function(key) { return section[key] })
}

function uriValues(item) {
  var uris = (item.login && Array.isArray(item.login.uris)) ? item.login.uris : []
  return uris.map(function(entry) { return (entry && entry.uri) ? entry.uri : entry })
}

function customFieldValues(item) {
  var fields = Array.isArray(item.fields) ? item.fields : []
  var values = []
  fields.forEach(function(field) {
    if (!field) return
    values.push(field.name)
    if (field.value !== undefined) values.push(field.value)
  })
  return values
}

// Searchable text of one redacted item, lower-cased.
function buildSearchText(item) {
  if (!item) return ""
  var values = [item.folder_name, item.organization_name]
    .concat(sectionValues(item.login, ["username"]))
    .concat(uriValues(item))
    .concat(sectionValues(item.card, ["brand", "cardholderName", "number_last_four"]))
    .concat(sectionValues(item.identity, ["firstName", "lastName", "email", "phone", "company", "address1", "city", "username"]))
    .concat(customFieldValues(item))
  return values.filter(function(value) { return value !== undefined && value !== null && value !== "" })
    .map(lower)
    .join(" ")
}

function queryWords(query) {
  return lower(query).trim().split(/\s+/).filter(Boolean)
}

function matchVaultScope(item, scope) {
  if (scope === "all") return true
  if (scope === "personal") return !item.organization_id
  return item.organization_id === scope || item.organization_name === scope
}

function matchFolderScope(item, scope) {
  if (scope === "all") return true
  if (scope === "none") return !item.folder_id && !item.folder_name
  return item.folder_id === scope || item.folder_name === scope
}

function matchCategory(item, category) {
  return category === "all" || item.type_name === category
}

function matchesFilters(item, filters) {
  return matchVaultScope(item, filters.vaultScope || "all")
    && matchFolderScope(item, filters.folderScope || "all")
    && matchCategory(item, filters.category || "all")
}

function wordScore(word, text) {
  for (var i = 0; i < WORD_MATCHERS.length; i++) {
    if (WORD_MATCHERS[i].matches(word, text)) return WORD_MATCHERS[i].score
  }
  return NO_MATCH
}

// Total score of an item for the query words, or NO_MATCH when any word
// matches nothing.
function scoreItem(item, words) {
  var text = {
    name: lower(item.name),
    subtitle: lower(item.sub_title),
    searchable: item.local_search_text !== undefined ? item.local_search_text : buildSearchText(item)
  }
  var total = item.favorite ? FAVORITE_SCORE : 0
  for (var i = 0; i < words.length; i++) {
    var score = wordScore(words[i], text)
    if (score === NO_MATCH) return NO_MATCH
    total += score
  }
  return total
}

// Items passing the scope and category filters, ranked for the query.
function filterItems(items, query, filters) {
  var words = queryWords(query)
  var scored = []
  ;(items || []).forEach(function(item) {
    if (!matchesFilters(item, filters)) return
    var score = scoreItem(item, words)
    if (score !== NO_MATCH) scored.push({ item: item, score: score })
  })
  scored.sort(function(a, b) { return b.score - a.score })
  return scored.map(function(entry) { return entry.item })
}

function indexOfItem(items, itemId) {
  if (!itemId) return 0
  for (var i = 0; i < items.length; i++) {
    if (items[i].id === itemId) return i
  }
  return 0
}
