#include <iostream>
#include <map>
#include <sstream>
#include <stdint.h>
#include <vector>
using namespace std;

template <typename T>

struct is_class_imp
{ //采用boost的type_traits的方式判断，判断一个类型是否是一个类类型

    typedef char class_type; //一个字节

    typedef int32_t non_class_type; //四个字节

    template <typename C> static class_type is_class_check(void (C::*)(void)); //类类型匹配到的模板函数

    template <typename C> static non_class_type is_class_check(...); //基础类型匹配到的模板函数

    static const bool value = (sizeof(is_class_check<T>(0)) == sizeof(class_type)); // value的值在编译期决定
};

template <>

struct is_class_imp<string>
{ //模板特化，string可以作为基础类型处理，其实是类类型

    static const bool value = false;
};

template <typename T>

struct is_class : is_class_imp<T>
{
}; //继承

template <bool C_>

struct bool_plt
{
}; //用于编译期条件判断的模板，bool_plt<true>和bool_plt<false>


    template <typename C_, typename F1, typename F2> // C_编译期的条件，依据条件判断，动态定义类型F1或F2

    struct eval_if
{
};

template <typename F1, typename F2> //模板偏特化，typename C_

struct eval_if<bool_plt<true>, F1, F2>
{ //当C_编译期条件为bool_plt<true>时，定义类型F1

    typedef F1 type;
};

template <typename F1, typename F2> //模板偏特化，typename C_

struct eval_if<bool_plt<false>, F1, F2>
{ //当C_编译期条件为bool_plt<false>时，定义类型F2

    typedef F2 type;
};

template <typename Archive, typename T>

class CAccess //对类类型对象，应该序列化还是反序列化的控制函数

{

  public:
    static void serialize(Archive &ar, T &t)
    { //调用类类型对象的serialize函数，序列化还是反序列化由ar参数决定

        t.serialize(ar);
    }
};

template <typename Archive, typename T>

struct CFreeMarshall
{ //序列化结构体类型

    static void invoke(Archive &ar, const T &t)
    {

        CAccess<Archive, T>::marshall(ar, t);
    }
};

template <typename Archive, typename T>

struct CFreeDemarshall
{ //反序列化结构体类型

    static void invoke(Archive &ar, T &t)
    {

        CAccess<Archive, T>::demarshall(ar, t);
    }
};

template <typename Archive, typename T>

struct CFreeInvoke
{ //序列化和反序列化统一调用模版函数，在编译期决定调用其一

    static void invoke(Archive &ar, T &t)
    {

        typedef typename eval_if<typename Archive::is_marshall, //假如ar对象是序列化对象

                                 CFreeMarshall<Archive, T>, //定义序列化类型

                                 CFreeDemarshall<Archive, T>>::type typex; //否则定义反序列化类型

        typex::invoke(ar, t); //调用序列化或反序列化函数，在编译期动态判断决定
    }
};

template <typename Archive, typename T>

class CAccess<Archive, vector<T>> //模板偏特化，实现vector容器的序列化和反序列化

{

  public:
    static void serialize(Archive &ar, vector<T> &t) //调用序列化或反序列化函数，在编译期动态判断决定

    {

        CFreeInvoke<Archive, vector<T>>::invoke(ar, t);
    }

    static void marshall(Archive &ar, const vector<T> &t) //序列化

    {

        int len = t.size();

        ar << len << " ";

        for (int i = 0; i < len; i++)

        {

            ar << t[i] << " ";
        }
    }

    static void demarshall(Archive &ar, vector<T> &t) //反序列化

    {

        int len = 0;

        ar >> len;

        t.clear();

        for (int i = 0; i < len; i++)

        {

            T tmp;

            ar >> tmp;

            t.push_back(tmp);
        }
    }
};

template <typename Archive, typename K, typename V>

class CAccess<Archive, map<K, V>> //模板偏特化，实现map容器的序列化和反序列化

{

  public:
    static void serialize(Archive &ar, map<K, V> &t) //调用序列化或反序列化函数，在编译期动态判断决定

    {

        CFreeInvoke<Archive, map<K, V>>::invoke(ar, t);
    }

    static void marshall(Archive &ar, const map<K, V> &t) //序列化

    {

        int len = t.size();

        ar << len << " ";

        typename map<K, V>::const_iterator iter;

        for (iter = t.begin(); iter != t.end(); ++iter)

            ar << iter->first << " " << iter->second << " ";
    }

    static void demarshall(Archive &ar, map<K, V> &t) //反序列化

    {

        int len = 0;

        ar >> len;

        t.clear();

        for (int i = 0; i < len; i++)

        {

            K key;

            V val;

            ar >> key >> val;

            t[key] = val;
        }
    }
};

class CTextSerialize //序列化和协议实现类

{

  public:
    typedef bool_plt<true> is_marshall; //该类定义为序列化类

    typedef bool_plt<false> is_demarshall;

    CTextSerialize(ostream &o) : os(o)
    {
    }

    template <typename T>

    void serialize(const T &t, bool_plt<false> &b) //基础类型序列化模板函数

    {

        os << t << " ";
    }

    template <typename T>

    void serialize(const T &t, bool_plt<true> &b) //类类型序列化模板函数

    {

        CAccess<CTextSerialize, T>::serialize(*this, const_cast<T &>(t));
    }

    template <typename T>

    CTextSerialize &operator<<(const T &t)

    {

        bool_plt<is_class<T>::value> type; // type在编译期确定，T是否是类类型

        serialize(t, type);

        return *this;
    }

    template <typename T>

    CTextSerialize &operator&(const T &t)

    {

        bool_plt<is_class<T>::value> type; // type在编译期确定，T是否是类类型

        serialize(t, type);

        return *this;
    }

  private:
    ostream &os;
};

class CTextDeserialize //反序列化和协议实现类

{

  public:
    typedef bool_plt<false> is_marshall;

    typedef bool_plt<true> is_demarshall; //该类定义为反序列化类

    CTextDeserialize(istream &i) : is(i)
    {
    }

    template <typename T>

    void deserialize(T &t, bool_plt<false> &b) //基础类型反序列化模板函数

    {

        is >> t;
    }

    template <typename T>

    void deserialize(T &t, bool_plt<true> &b) //类类型反序列化模板函数

    {

        CAccess<CTextDeserialize, T>::serialize(*this, t);
    }

    template <typename T>

    CTextDeserialize &operator>>(T &t)

    {

        bool_plt<is_class<T>::value> type; // type在编译期确定，T是否是类类型

        deserialize(t, type);

        return *this;
    }

    template <typename T>

    CTextDeserialize &operator&(T &t)

    {

        bool_plt<is_class<T>::value> type; // type在编译期确定，T是否是类类型

        deserialize(t, type);

        return *this;
    }

  private:
    istream &is;
};

enum EName
{
};

struct SData
{
};

class CData //支持序列化和反序列化的类实现

{

  private: //待序列化的成员变量
    uint32_t ver;

    int i;

    bool b;

    long l;

    double d;

    string s;

    vector<string> vecStr;

    map<int, string> mapInfo;

  public:
    CData() : ver(0), i(0), b(false), l(0), d(0)
    {
    } //数据初始化

    void init(uint32_t ver, int i, bool b, long l, double d, string s, string arr[], int len)

    {

        this->ver = ver;

        this->i = i;

        this->b = b;

        this->l = l;

        this->d = d;

        this->s = s;

        this->vecStr.assign(arr, arr + len);

        for (int j = 0; j < len; j++)

            mapInfo[j] = arr[j];
    }

    template <typename Archive> //模板多态，Archive可以实现多种序列化协议

    Archive &serialize(Archive &ar) //序列化和反序列化都调用这个模板函数

    {

        ar &ver;

        ar &i;

        ar &b;

        ar &l;

        ar &d;

        ar &s;

        ar &vecStr;

        ar &mapInfo;

        return ar;
    }

    string tostr(void) //便于类对象打印输出

    {

        stringstream ss;

        ss << " ver " << ver

           << " int:" << i << " bool:" << (true == b ? "true" : "false")

           << " long:" << l << " double:" << d << " string:" << s;

        int len = vecStr.size();

        ss << " vector:" << len << " ";

        for (int j = 0; j < len; j++)
            ss << vecStr[j] << " ";

        ss << " map:" << len << " ";

        for (int j = 0; j < len; j++)
            ss << j << " " << mapInfo[j] << " ";

        return ss.str();
    }
};

int main(void)

{

    { //将数据存入流中，将数据从流中取出；空格做为数据分隔符，简单的数据存储格式

        stringstream ss;

        int a = 1;

        double b = 2.1;

        string c = "abc";

        ss << a << " " << b << " " << c;

        int A = 0;

        double B = 0;

        string C;

        ss >> A >> B >> C;

        cout << ss.str() << endl;

        cout << A << " " << B << " " << C << endl << endl;
    }

    { //使用模板方式，在编译期判断数据类型，是否是类类型

        cout << is_class<int>::value << endl; //该代码块都是基础数据类型

        cout << is_class<double>::value << endl;

        cout << is_class<EName>::value << endl;

        cout << is_class<string>::value << endl;

        cout << is_class<CData>::value << endl; //该代码块都是类类型

        cout << is_class<SData>::value << endl;

        cout << is_class<vector<int>>::value << endl << endl;
    }

    { //序列化和反序列化基础数据类型

        int a = 1;

        double b = 2.1;

        string c = "abc";

        std::ostringstream os;

        CTextSerialize oSer(os);

        oSer << a << b << c;

        cout << a << " " << b << " " << c << endl;

        int A = 0;

        double B = 0;

        string C;

        std::istringstream is(os.str());

        CTextDeserialize iDeser(is);

        iDeser >> A >> B >> C;

        cout << A << " " << B << " " << C << endl << endl;
    }

    { //序列化和反序列化类类型

        string arr[] = {"3a", "2b", "1c"};

        int len = sizeof(arr) / sizeof(arr[0]); // C++内存布局与C语言兼容

        CData oData;

        oData.init(0, 11, true, 222, 3.30, "string", arr, len);

        std::ostringstream os;

        CTextSerialize oSer(os);

        oSer << oData;

        cout << "oData:" << oData.tostr() << endl;

        CData iData;

        std::istringstream is(os.str());

        CTextDeserialize iDeser(is);

        iDeser >> iData;

        cout << "iData:" << iData.tostr() << endl;
    }

    return 0;
}