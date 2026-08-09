/*
 * Copyright (C) 2005 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_STRING8_H
#define ANDROID_STRING8_H

#include <iostream>
#include <string>
#include <string_view>

#include <utils/Errors.h>
#include <utils/Unicode.h>
#include <utils/TypeHelpers.h>

#include <string.h> // for strcmp
#include <stdarg.h>

#if __cplusplus >= 202002L
#include <compare>
#endif

// ---------------------------------------------------------------------------

namespace android {

class String16;

// DO NOT USE: please use std::string

//! This is a string holding UTF-8 characters. Does not allow the value more
// than 0x10FFFF, which is not valid unicode codepoint.
class String8
{
public:
                                String8();
                                String8(const String8& o);
    explicit                    String8(const char* o);
    explicit                    String8(const char* o, size_t numChars);
    explicit                    String8(std::string_view o);

    explicit                    String8(const String16& o);
    explicit                    String8(const char16_t* o);
    explicit                    String8(const char16_t* o, size_t numChars);
    explicit                    String8(const char32_t* o);
    explicit                    String8(const char32_t* o, size_t numChars);
                                ~String8();

    static String8              format(const char* fmt, ...) __attribute__((format (printf, 1, 2)));
    static String8              formatV(const char* fmt, va_list args);

    inline  const char*         c_str() const;

    inline  size_t              size() const;
    inline  size_t              bytes() const;
    inline  bool                empty() const;

            size_t              length() const;

            void                clear();

            void                setTo(const String8& other);
            status_t            setTo(const char* other);
            status_t            setTo(const char* other, size_t numChars);
            status_t            setTo(const char16_t* other, size_t numChars);
            status_t            setTo(const char32_t* other,
                                      size_t length);

            status_t            append(const String8& other);
            status_t            append(const char* other);
            status_t            append(const char* other, size_t numChars);

            status_t            appendFormat(const char* fmt, ...)
                    __attribute__((format (printf, 2, 3)));
            status_t            appendFormatV(const char* fmt, va_list args);

    inline  String8&            operator=(const String8& other);
    inline  String8&            operator=(const char* other);

    inline  String8&            operator+=(const String8& other);
    inline  String8             operator+(const String8& other) const;

    inline  String8&            operator+=(const char* other);
    inline  String8             operator+(const char* other) const;

    inline  int                 compare(const String8& other) const;

    inline  bool                operator<(const String8& other) const;
    inline  bool                operator<=(const String8& other) const;
    inline  bool                operator==(const String8& other) const;
    inline  bool                operator!=(const String8& other) const;
    inline  bool                operator>=(const String8& other) const;
    inline  bool                operator>(const String8& other) const;
#if __cplusplus >= 202002L
    inline std::strong_ordering operator<=>(const String8& other) const;
#endif

    inline  bool                operator<(const char* other) const;
    inline  bool                operator<=(const char* other) const;
    inline  bool                operator==(const char* other) const;
    inline  bool                operator!=(const char* other) const;
    inline  bool                operator>=(const char* other) const;
    inline  bool                operator>(const char* other) const;
#if __cplusplus >= 202002L
    inline std::strong_ordering operator<=>(const char* other) const;
#endif

    inline                      operator const char*() const;

    inline explicit             operator std::string_view() const;

            char*               lockBuffer(size_t size);
            void                unlockBuffer();
            status_t            unlockBuffer(size_t size);

            // return the index of the first byte of other in this at or after
            // start, or -1 if not found
            ssize_t             find(const char* other, size_t start = 0) const;
    inline  ssize_t             find(const String8& other, size_t start = 0) const;

            // return true if this string contains the specified substring
    inline  bool                contains(const char* other) const;
    inline  bool                contains(const String8& other) const;

            // removes all occurrence of the specified substring
            // returns true if any were found and removed
            bool                removeAll(const char* other);
    inline  bool                removeAll(const String8& other);

            void                toLower();

private:
            String8 getPathDir(void) const;
            String8 getPathExtension(void) const;

            status_t            real_append(const char* other, size_t numChars);

            const char* mString;

// These symbols are for potential backward compatibility with prebuilts. To be removed.
#ifdef ENABLE_STRING8_OBSOLETE_METHODS
public:
#else
private:
#endif
    inline  const char*         string() const;
    inline  bool                isEmpty() const;
};

// String8 can be trivially moved using memcpy() because moving does not
// require any change to the underlying SharedBuffer contents or reference count.
ANDROID_TRIVIAL_MOVE_TRAIT(String8)

static inline std::ostream& operator<<(std::ostream& os, const String8& str) {
    os << str.c_str();
    return os;
}

// ---------------------------------------------------------------------------
// No user servicable parts below.

inline int compare_type(const String8& lhs, const String8& rhs)
{
    return lhs.compare(rhs);
}

inline int strictly_order_type(const String8& lhs, const String8& rhs)
{
    return compare_type(lhs, rhs) < 0;
}

inline const char* String8::c_str() const
{
    return mString;
}
inline const char* String8::string() const
{
    return mString;
}

inline size_t String8::size() const
{
    return length();
}

inline bool String8::empty() const
{
    return length() == 0;
}

inline bool String8::isEmpty() const
{
    return length() == 0;
}

inline size_t String8::bytes() const
{
    return length();
}

inline ssize_t String8::find(const String8& other, size_t start) const
{
    return find(other.c_str(), start);
}

inline bool String8::contains(const char* other) const
{
    return find(other) >= 0;
}

inline bool String8::contains(const String8& other) const
{
    return contains(other.c_str());
}

inline bool String8::removeAll(const String8& other)
{
    return removeAll(other.c_str());
}

inline String8& String8::operator=(const String8& other)
{
    setTo(other);
    return *this;
}

inline String8& String8::operator=(const char* other)
{
    setTo(other);
    return *this;
}

inline String8& String8::operator+=(const String8& other)
{
    append(other);
    return *this;
}

inline String8 String8::operator+(const String8& other) const
{
    String8 tmp(*this);
    tmp += other;
    return tmp;
}

inline String8& String8::operator+=(const char* other)
{
    append(other);
    return *this;
}

inline String8 String8::operator+(const char* other) const
{
    String8 tmp(*this);
    tmp += other;
    return tmp;
}

inline int String8::compare(const String8& other) const
{
    return strcmp(mString, other.mString);
}

inline bool String8::operator<(const String8& other) const
{
    return strcmp(mString, other.mString) < 0;
}

inline bool String8::operator<=(const String8& other) const
{
    return strcmp(mString, other.mString) <= 0;
}

inline bool String8::operator==(const String8& other) const
{
    return strcmp(mString, other.mString) == 0;
}

inline bool String8::operator!=(const String8& other) const
{
    return strcmp(mString, other.mString) != 0;
}

inline bool String8::operator>=(const String8& other) const
{
    return strcmp(mString, other.mString) >= 0;
}

inline bool String8::operator>(const String8& other) const
{
    return strcmp(mString, other.mString) > 0;
}

#if __cplusplus >= 202002L
inline std::strong_ordering String8::operator<=>(const String8& other) const {
    int result = strcmp(mString, other.mString);
    if (result == 0) {
        return std::strong_ordering::equal;
    } else if (result < 0) {
        return std::strong_ordering::less;
    } else {
        return std::strong_ordering::greater;
    }
}
#endif

inline bool String8::operator<(const char* other) const
{
    return strcmp(mString, other) < 0;
}

inline bool String8::operator<=(const char* other) const
{
    return strcmp(mString, other) <= 0;
}

inline bool String8::operator==(const char* other) const
{
    return strcmp(mString, other) == 0;
}

inline bool String8::operator!=(const char* other) const
{
    return strcmp(mString, other) != 0;
}

inline bool String8::operator>=(const char* other) const
{
    return strcmp(mString, other) >= 0;
}

inline bool String8::operator>(const char* other) const
{
    return strcmp(mString, other) > 0;
}

#if __cplusplus >= 202002L
inline std::strong_ordering String8::operator<=>(const char* other) const {
    int result = strcmp(mString, other);
    if (result == 0) {
        return std::strong_ordering::equal;
    } else if (result < 0) {
        return std::strong_ordering::less;
    } else {
        return std::strong_ordering::greater;
    }
}
#endif

inline String8::operator const char*() const
{
    return mString;
}

inline String8::String8(std::string_view o) : String8(o.data(), o.length()) { }

inline String8::operator std::string_view() const
{
    return {mString, length()};
}

}  // namespace android

// ---------------------------------------------------------------------------

#endif // ANDROID_STRING8_H
