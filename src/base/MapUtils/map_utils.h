//
// Copyright (C) 2021 Stealth Software Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//

// Description: Helper functions for Maps.

#ifndef MAP_UTILS_H
#define MAP_UTILS_H

#include <cstdlib>
#include <map>
#include <set>

namespace map_utils {

// Returns the set of Keys for the input map.
template<typename Key, typename Value>
inline std::set<Key> Keys(const std::map<Key, Value>& input) {
  std::set<Key> to_return;
  for (const std::pair<const Key, Value>& itr : input) {
    to_return.insert(itr.first);
  }
  return to_return;
}

// Returns true if key is in the set.
template<typename Key>
inline bool ContainsKey(Key k, const std::set<Key>& input) {
  return input.find(k) != input.end();
}

// Same as above, for map.
template<typename Key, typename Value>
inline bool ContainsKey(Key k, const std::map<Key, Value>& input) {
  return input.find(k) != input.end();
}

// Inserts ('key', 'value') to the indicated map, overwriting any Value that
// may already be present with that 'key'.
// Returns true if the key already existed (and so a value was overwritten).
template<typename Key, typename Value>
inline bool InsertOrReplace(std::map<Key, Value>& input, Key k, Value v) {
  std::pair<typename std::map<Key, Value>::iterator, bool> insert_info =
      input.insert(std::make_pair(k, v));
  if (!insert_info.second) insert_info.first->second = v;
  return !insert_info.second;
}

// Either returns a pointer to the existing Value corresponding to 'key' (after
// inserting ('key', 'value') into the map if 'key' was not already present.
template<typename Key, typename Value>
inline Value* FindOrInsert(
    const Key& key, std::map<Key, Value>& input, const Value& default_value) {
  typename std::map<Key, Value>::iterator itr = input.find(key);
  if (itr == input.end()) {
    return &(input.insert(std::make_pair(key, default_value)).first->second);
  }
  return &(itr->second);
}

// Same as above, but doesn't modify the map (if key does not exist, just
// returns the default value).
template<typename Key, typename Value>
inline Value FindWithDefault(
    const Key& key,
    const std::map<Key, Value>& input,
    const Value& default_value) {
  typename std::map<Key, Value>::const_iterator itr = input.find(key);
  if (itr == input.end()) {
    return default_value;
  }
  return itr->second;
}

// Returns a pointer to the Value corresponding to 'key', or nullptr
// if 'key' does not exist in the input map.
template<typename Key, typename Value>
inline Value* FindOrNull(const Key& key, std::map<Key, Value>& input) {
  typename std::map<Key, Value>::iterator itr = input.find(key);
  if (itr == input.end()) return nullptr;
  return &(itr->second);
}
// Same above, but returns const reference.
template<typename Key, typename Value>
inline const Value* FindOrNull(
    const Key& key, const std::map<Key, Value>& input) {
  typename std::map<Key, Value>::const_iterator itr = input.find(key);
  if (itr == input.end()) return nullptr;
  return &(itr->second);
}
// Same above, but also the map values are const.
template<typename Key, typename Value>
inline const Value* FindOrNull(
    const Key& key, const std::map<Key, const Value>& input) {
  typename std::map<Key, Value>::const_iterator itr = input.find(key);
  if (itr == input.end()) return nullptr;
  return &(itr->second);
}

}  // namespace map_utils

#endif
