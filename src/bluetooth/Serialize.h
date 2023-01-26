#include "../../include/types.h"
#include <iostream>
#include <map>
#include <sstream>
#include <string.h>
#include <vector>

using namespace std;

class StreamBuf {
public:
  StreamBuf(u8 *_buf) : buf(_buf), cur(buf) {}
  u32 write(const void *src, u32 size) {
    memcpy(cur, src, size);
    cur += size;
    return size;
  }

  u32 read(void *dst, u32 size) {
    memcpy(dst, cur, size);
    cur += size;
    return size;
  }

  u32 len() { return cur - buf; }

private:
  u8 *buf;
  u8 *cur;
};

template <bool C_> struct bool_plt {};

template <typename C_, typename F1, typename F2> struct eval_if {};

template <typename F1, typename F2> struct eval_if<bool_plt<true>, F1, F2> {
  typedef F1 type;
};

template <typename F1, typename F2> struct eval_if<bool_plt<false>, F1, F2> {
  typedef F2 type;
};

template <typename Archive, typename T> class CAccess {
public:
  static void serialize(Archive &ar, T &t) { t.serialize(ar); }
};

template <typename Archive, typename T> struct CFreeMarshall {
  static void invoke(Archive &ar, const T &t) {
    CAccess<Archive, T>::marshall(ar, t);
  }
};

template <typename Archive, typename T> struct CFreeDemarshall {
  static void invoke(Archive &ar, T &t) {
    CAccess<Archive, T>::demarshall(ar, t);
  }
};

template <typename Archive, typename T> struct CFreeInvoke {
  static void invoke(Archive &ar, T &t) {
    typedef typename eval_if<typename Archive::is_marshall,
                             CFreeMarshall<Archive, T>,
                             CFreeDemarshall<Archive, T>>::type typex;
    typex::invoke(ar, t);
  }
};

template <typename Archive, typename T> class CAccess<Archive, vector<T>> {
public:
  static void serialize(Archive &ar, vector<T> &t) {
    CFreeInvoke<Archive, vector<T>>::invoke(ar, t);
  }

  static void marshall(Archive &ar, const vector<T> &t) {
    u32 len = t.size();
    ar << len;
    for (int i = 0; i < len; i++) {
      ar << t[i];
    }
  }

  static void demarshall(Archive &ar, vector<T> &t) {
    u32 len = 0;
    ar >> len;
    t.resize(len);
    for (int i = 0; i < len; i++) {
      ar >> t[i];
    }
  }
};

class BinarySerialize {
public:
  typedef bool_plt<true> is_marshall;
  typedef bool_plt<false> is_demarshall;

  BinarySerialize(u8 *buf) : os(buf) {}

  template <typename T> void serialize(const T &t, bool_plt<false> &b) {
    os.write(&t, sizeof(T));
  }

  template <typename T> void serialize(const T &t, bool_plt<true> &b) {
    CAccess<BinarySerialize, T>::serialize(*this, const_cast<T &>(t));
  }

  template <typename T> BinarySerialize &operator<<(const T &t) {
    bool_plt<is_class<T>::value> type;
    serialize(t, type);
    return *this;
  }

  template <typename T> BinarySerialize &operator&(const T &t) {
    bool_plt<is_class<T>::value> type;
    serialize(t, type);
    return *this;
  }

  u32 len() {return os.len();}

private:
  StreamBuf os;
};

class BinaryDeserialize {
public:
  typedef bool_plt<false> is_marshall;
  typedef bool_plt<true> is_demarshall;

  BinaryDeserialize(u8 *buf) : is(buf) {}

  template <typename T> void deserialize(T &t, bool_plt<false> &b) {
    is.read(&t, sizeof(T));
  }

  template <typename T> void deserialize(T &t, bool_plt<true> &b) {
    CAccess<BinaryDeserialize, T>::serialize(*this, t);
  }

  template <typename T> BinaryDeserialize &operator>>(T &t) {
    bool_plt<is_class<T>::value> type;
    deserialize(t, type);
    return *this;
  }

  template <typename T> BinaryDeserialize &operator&(T &t) {
    bool_plt<is_class<T>::value> type;
    deserialize(t, type);
    return *this;
  }

private:
  StreamBuf is;
};