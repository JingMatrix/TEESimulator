#include "json.hpp"

#include <cstdlib>
#include <cstring>

namespace tjson {

namespace {

// Shared fallbacks handed out by the total accessors. They are const, so the
// aliasing is harmless.
const Value kNull;
const std::string kEmptyString;

// Encodes a Unicode code point as UTF-8 and appends it to out. cp is always a
// valid scalar value (<= 0x10FFFF, no surrogates) by the time this is called.
void append_utf8(std::string &out, uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

} // namespace

// A recursive-descent parser over a bounded byte buffer. Every read is guarded
// against the end of the buffer, and recursion depth is passed down explicitly
// so the container parsers can reject documents nested beyond kMaxDepth.
struct Parser {
    const char *p;
    size_t n;
    size_t i = 0;

    static constexpr int kMaxDepth = 200;

    bool eof() const { return i >= n; }

    void skip_ws() {
        while (i < n) {
            char c = p[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++i;
            } else {
                break;
            }
        }
    }

    // Matches a bare literal (true / false / null) starting at the cursor.
    bool match_literal(const char *lit) {
        size_t l = std::strlen(lit);
        if (i + l > n || std::memcmp(p + i, lit, l) != 0) {
            return false;
        }
        i += l;
        return true;
    }

    // Reads exactly four hex digits into out, advancing the cursor on success.
    bool read_hex4(uint32_t &out) {
        if (i + 4 > n) {
            return false;
        }
        uint32_t v = 0;
        for (int k = 0; k < 4; ++k) {
            char c = p[i + k];
            v <<= 4;
            if (c >= '0' && c <= '9') {
                v |= static_cast<uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                v |= static_cast<uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                v |= static_cast<uint32_t>(c - 'A' + 10);
            } else {
                return false;
            }
        }
        i += 4;
        out = v;
        return true;
    }

    // Parses a JSON string, with the cursor sitting on the opening quote.
    bool parse_string(std::string &out) {
        ++i; // consume opening quote
        while (true) {
            if (eof()) {
                return false; // unterminated string
            }
            unsigned char c = static_cast<unsigned char>(p[i]);
            if (c == '"') {
                ++i;
                return true;
            }
            if (c == '\\') {
                ++i;
                if (eof()) {
                    return false;
                }
                char e = p[i++];
                switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    uint32_t cp;
                    if (!read_hex4(cp)) {
                        return false;
                    }
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        // High surrogate: must be followed by \uXXXX low surrogate.
                        if (i + 2 > n || p[i] != '\\' || p[i + 1] != 'u') {
                            return false;
                        }
                        i += 2;
                        uint32_t lo;
                        if (!read_hex4(lo)) {
                            return false;
                        }
                        if (lo < 0xDC00 || lo > 0xDFFF) {
                            return false;
                        }
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return false; // lone low surrogate
                    }
                    append_utf8(out, cp);
                    break;
                }
                default:
                    return false; // invalid escape
                }
            } else if (c < 0x20) {
                return false; // raw control character
            } else {
                // Any other byte, including UTF-8 continuation bytes, passes
                // through verbatim.
                out.push_back(static_cast<char>(c));
                ++i;
            }
        }
    }

    // Parses a JSON number, with the cursor on '-' or a digit.
    bool parse_number(Value &out) {
        size_t start = i;

        if (i < n && p[i] == '-') {
            ++i;
        }
        // Integer part: a lone 0, or a nonzero digit followed by more digits.
        if (eof()) {
            return false;
        }
        if (p[i] == '0') {
            ++i;
        } else if (p[i] >= '1' && p[i] <= '9') {
            ++i;
            while (i < n && p[i] >= '0' && p[i] <= '9') {
                ++i;
            }
        } else {
            return false;
        }

        bool is_int = true;

        if (i < n && p[i] == '.') {
            is_int = false;
            ++i;
            if (i >= n || p[i] < '0' || p[i] > '9') {
                return false; // need at least one fractional digit
            }
            while (i < n && p[i] >= '0' && p[i] <= '9') {
                ++i;
            }
        }

        if (i < n && (p[i] == 'e' || p[i] == 'E')) {
            is_int = false;
            ++i;
            if (i < n && (p[i] == '+' || p[i] == '-')) {
                ++i;
            }
            if (i >= n || p[i] < '0' || p[i] > '9') {
                return false; // need at least one exponent digit
            }
            while (i < n && p[i] >= '0' && p[i] <= '9') {
                ++i;
            }
        }

        std::string tok(p + start, i - start);
        out.type_ = Value::Number;

        if (is_int) {
            bool neg = tok[0] == '-';
            size_t k = neg ? 1 : 0;
            int64_t val = 0;
            bool overflow = false;
            for (; k < tok.size(); ++k) {
                int d = tok[k] - '0';
                if (val > (INT64_MAX - d) / 10) {
                    overflow = true;
                    break;
                }
                val = val * 10 + d;
            }
            if (!overflow) {
                out.int_ = neg ? -val : val;
                out.int_exact_ = true;
                out.dbl_ = static_cast<double>(out.int_);
                return true;
            }
            // Fall through to the double path for integers too large for int64.
        }

        out.int_exact_ = false;
        out.dbl_ = std::strtod(tok.c_str(), nullptr);
        out.int_ = static_cast<int64_t>(out.dbl_);
        return true;
    }

    bool parse_array(Value &out, int depth) {
        ++i; // consume '['
        out.type_ = Value::Array;
        skip_ws();
        if (eof()) {
            return false;
        }
        if (p[i] == ']') {
            ++i;
            return true;
        }
        while (true) {
            Value v;
            if (!parse_value(v, depth + 1)) {
                return false;
            }
            out.arr_.push_back(std::move(v));
            skip_ws();
            if (eof()) {
                return false;
            }
            if (p[i] == ',') {
                ++i;
                continue;
            }
            if (p[i] == ']') {
                ++i;
                return true;
            }
            return false;
        }
    }

    bool parse_object(Value &out, int depth) {
        ++i; // consume '{'
        out.type_ = Value::Object;
        skip_ws();
        if (eof()) {
            return false;
        }
        if (p[i] == '}') {
            ++i;
            return true;
        }
        while (true) {
            skip_ws();
            if (eof() || p[i] != '"') {
                return false;
            }
            std::string key;
            if (!parse_string(key)) {
                return false;
            }
            skip_ws();
            if (eof() || p[i] != ':') {
                return false;
            }
            ++i;
            Value v;
            if (!parse_value(v, depth + 1)) {
                return false;
            }
            // Last occurrence of a duplicate key wins.
            bool replaced = false;
            for (auto &kv : out.obj_) {
                if (kv.first == key) {
                    kv.second = std::move(v);
                    replaced = true;
                    break;
                }
            }
            if (!replaced) {
                out.obj_.emplace_back(std::move(key), std::move(v));
            }
            skip_ws();
            if (eof()) {
                return false;
            }
            if (p[i] == ',') {
                ++i;
                continue;
            }
            if (p[i] == '}') {
                ++i;
                return true;
            }
            return false;
        }
    }

    bool parse_value(Value &out, int depth) {
        if (depth > kMaxDepth) {
            return false;
        }
        skip_ws();
        if (eof()) {
            return false;
        }
        char c = p[i];
        switch (c) {
        case '{':
            return parse_object(out, depth);
        case '[':
            return parse_array(out, depth);
        case '"':
            out.type_ = Value::String;
            return parse_string(out.str_);
        case 't':
            if (!match_literal("true")) {
                return false;
            }
            out.type_ = Value::Bool;
            out.bool_ = true;
            return true;
        case 'f':
            if (!match_literal("false")) {
                return false;
            }
            out.type_ = Value::Bool;
            out.bool_ = false;
            return true;
        case 'n':
            if (!match_literal("null")) {
                return false;
            }
            out.type_ = Value::Null;
            return true;
        default:
            if (c == '-' || (c >= '0' && c <= '9')) {
                return parse_number(out);
            }
            return false;
        }
    }
};

const Value *Value::get(const std::string &key) const {
    if (type_ != Object) {
        return nullptr;
    }
    for (const auto &kv : obj_) {
        if (kv.first == key) {
            return &kv.second;
        }
    }
    return nullptr;
}

size_t Value::size() const {
    return type_ == Array ? arr_.size() : 0;
}

const Value &Value::at(size_t i) const {
    if (type_ != Array || i >= arr_.size()) {
        return kNull;
    }
    return arr_[i];
}

bool Value::as_bool(bool def) const {
    return type_ == Bool ? bool_ : def;
}

int64_t Value::as_int(int64_t def) const {
    return type_ == Number ? int_ : def;
}

double Value::as_double(double def) const {
    return type_ == Number ? dbl_ : def;
}

const std::string &Value::as_string() const {
    return type_ == String ? str_ : kEmptyString;
}

bool parse(const char *data, size_t len, Value &out) {
    out = Value();
    if (data == nullptr) {
        return false;
    }
    Parser ps{data, len};
    if (!ps.parse_value(out, 0)) {
        return false;
    }
    ps.skip_ws();
    return ps.eof(); // reject trailing garbage after the top-level value
}

} // namespace tjson
