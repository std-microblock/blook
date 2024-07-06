#pragma once

namespace blook::xtd {

namespace msvc {

template <typename T>
class basic_string {
private:
  static constexpr size_t BUFSIZE = 16 / sizeof(T);
  union {
    T *ptr;
    T buf[BUFSIZE];
  };
  size_t size;
  size_t res;

  bool _Large_mode_engaged() const noexcept {
    return res > 0xF;
  }

public:
  T *data() noexcept {
    return _Large_mode_engaged() ? ptr : buf;
  }
};

using string = basic_string<char>;

} // namespace msvc

namespace gcc {

template <typename T>
class basic_string {
private:
  static constexpr size_t _S_local_capacity = 15 / sizeof(T);
  T *_M_p;
  size_t _M_string_length;
  union {
    T _M_local_buf[_S_local_capacity + 1];
    size_t _M_allocated_capacity;
  };
};

using string = basic_string<char>;

} // namespace gcc

namespace clang {

template <typename T>
class basic_string {
private:
  struct __long {
    size_t __is_long_ : 1;
    size_t __cap_ : sizeof(size_t) * CHAR_BIT - 1;
    size_t __size_;
    T *__data_;
  };

  static constexpr size_t __min_cap = (sizeof(__long) - 1) / sizeof(T) > 2
                                          ? (sizeof(__long) - 1) / sizeof(T)
                                          : 2;

  struct __short {
    unsigned char __is_long_ : 1;
    unsigned char __size_ : 7;
    // char __padding_[sizeof(T) - 1]; // MSVC does not support arr[0]
    T __data_[__min_cap];
  };

  static_assert(
      sizeof(__short) == (sizeof(T) * (__min_cap + 1)),
      "__short has an unexpected size.");

  union __rep {
    __short __s;
    __long __l;
  };

  __rep __r_;

  bool __is_long() const noexcept {
    return __r_.__l.__is_long_;
    // return __r_.__s.__is_long_;
  }

  T *__get_short_pointer() noexcept {
    return __r_.__s.__data_;
  }

  const T *__get_short_pointer() const noexcept {
    return __r_.__s.__data_;
  }

  T *__get_long_pointer() noexcept {
    return __r_.__l.__data_;
  }

  const T *__get_long_pointer() const noexcept {
    return __r_.__l.__data_;
  }

  T *__get_pointer() noexcept {
    return __is_long() ? __get_long_pointer() : __get_short_pointer();
  }

  const T *__get_pointer() const noexcept {
    return __is_long() ? __get_long_pointer() : __get_short_pointer();
  }

  size_t __get_long_size() const noexcept {
    return __r_.__l.__size_;
  }

  size_t __get_short_size() const noexcept {
    return __r_.__s.__size_;
  }

  size_t __get_long_cap() const noexcept {
    return __r_.__l.__cap_;
  }

public:
  T *data() noexcept {
    return __get_pointer();
  }

  size_t capacity() const noexcept {
    return (__is_long() ? __get_long_cap() : static_cast<size_t>(__min_cap)) -
           1;
  }

  size_t size() const noexcept {
    return __is_long() ? __get_long_size() : __get_short_size();
  }
};

using string = basic_string<char>;

} // namespace clang

enum Platform {
  Unknown = 0,
  Msvc,
  Gcc,
  Clang,
};

template <typename T>
struct basic_string {
  size_t gap[3];
};

using string = basic_string<char>;

template <typename T>
class XBasicString {
public:
  XBasicString(basic_string<T> *data, Platform platform)
      : raw(data), platform(platform) {
  }

  char *data() noexcept {
    switch (platform) {
    case Platform::Msvc:
      return reinterpret_cast<msvc::basic_string<T> *>(raw)->data();
    case Platform::Gcc:
      return (char *)"";
    case Platform::Clang:
      return reinterpret_cast<clang::basic_string<T> *>(raw)->data();
    default:
      return nullptr;
    }
  }

  const char *data() const noexcept {
    switch (platform) {
    case Platform::Msvc:
      return reinterpret_cast<msvc::basic_string<T> *>(raw)->data();
    case Platform::Gcc:
      return (char *)"";
    case Platform::Clang:
      return reinterpret_cast<clang::basic_string<T> *>(raw)->data();
    default:
      return nullptr;
    }
  }

private:
  Platform platform;
  basic_string<T> *raw;
};

using XString = XBasicString<char>;

} // namespace blook::xtd
