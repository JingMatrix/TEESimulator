#ifndef TJSON_JSON_HPP
#define TJSON_JSON_HPP

// A tiny, dependency-free JSON reader for use inside a native Android library.
//
// This parser is built to link into code compiled with -fno-exceptions and
// -fno-rtti. It never throws, never aborts, and never over-reads its input:
// every malformed, truncated, or hostile document is rejected by returning
// false from parse(). Accessors are total functions that fall back to a
// caller-supplied default (or a shared empty/null instance) whenever the
// underlying type does not match, so callers never need to check before asking.

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace tjson {

// An immutable node of a parsed JSON document. A Value owns its children, so a
// single root keeps the whole tree alive; copying a Value deep-copies it.
class Value {
public:
    enum Type { Null, Bool, Number, String, Array, Object };

    Value() = default;

    Type type() const { return type_; }
    bool is_null() const { return type_ == Null; }
    bool is_bool() const { return type_ == Bool; }
    bool is_number() const { return type_ == Number; }
    bool is_string() const { return type_ == String; }
    bool is_array() const { return type_ == Array; }
    bool is_object() const { return type_ == Object; }

    // Object lookup. Returns nullptr when this Value is not an object or the key
    // is absent. When a document repeats a key, the last occurrence wins.
    const Value *get(const std::string &key) const;

    // Array access. size() is 0 for anything that is not an array. at(i) returns
    // a reference to a shared static Null value when i is out of range or this
    // Value is not an array, so the result is always safe to dereference.
    size_t size() const;
    const Value &at(size_t i) const;

    // Scalar accessors. Each returns the supplied default (or a reference to a
    // shared empty string) when the stored type does not match the request.
    bool as_bool(bool def = false) const;
    int64_t as_int(int64_t def = 0) const;
    double as_double(double def = 0.0) const;
    const std::string &as_string() const;

private:
    friend struct Parser;

    Type type_ = Null;
    bool bool_ = false;
    // For a Number, dbl_ always holds the value. int_exact_ records whether the
    // source token was an integer that fit in int64_t, in which case int_ holds
    // the exact value (so digits like 20250805 survive without double rounding).
    bool int_exact_ = false;
    int64_t int_ = 0;
    double dbl_ = 0.0;
    std::string str_;
    std::vector<Value> arr_;
    std::vector<std::pair<std::string, Value>> obj_;
};

// Parses len bytes of UTF-8 JSON. On success returns true and populates out; on
// any syntax error returns false and leaves out unspecified. Safe on arbitrary,
// malformed, or truncated input: no over-read, no crash, no allocation on a null
// pointer. Nesting is capped, so pathological input cannot exhaust the stack.
bool parse(const char *data, size_t len, Value &out);

} // namespace tjson

#endif // TJSON_JSON_HPP
