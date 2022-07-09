#pragma once

#include <chrono>
#include <thread>
#include <TlHelp32.h>
#include <math.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <tlhelp32.h>
#include <psapi.h>
#include <functional>
#include <sstream>
#include <iomanip>
#include <array>
#include <utility>
#include <Windows.h>

using namespace std::string_literals;

typedef long long ll;
typedef unsigned long long ull;
typedef size_t ADDRESS;
typedef size_t index;
typedef unsigned char byte;
typedef int64_t i64;
typedef int32_t i32;
typedef int16_t i16;
typedef int8_t  i8;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

// Compilator-specific things
#ifdef _MSC_VER
#define fastfunc __forceinline
#else
#define fastfunc __attribute__((always_inline))
#endif

#define funcerror(text) std::cerr<<std::dec<< __func__<< " -> "<< text<< ". ec: "<< GetLastError()<< std::endl<<'\t'<<__FILE__<<'\t'<<__LINE__<<std::endl;
#define astype(_class, _func) decltype( std::declval<_class>()._func )

class Application;
class Pattern;
class RAM;
class DllModule;
class Offset;
class Rand;
template <typename DataType> class Item;
struct CEbytearr;

int wstrcmp(const wchar_t *str1, const wchar_t *str2)
{
    return std::wstring(str1).compare(std::wstring(str2));
}


class Pattern
{
    bool match(std::vector<BYTE, std::allocator<BYTE>> bytes)
    {
        if ( this->bytes.size() == bytes.size() ) return static_cast<bool>(std::equal(this->bytes.begin(), this->bytes.end(), bytes.begin()));
        return 0;
    }

    bool match(std::vector<bool, std::allocator<bool>> pattern)
    {
        if ( this->mask.size() == pattern.size() ) return static_cast<bool>(std::equal(this->mask.begin(), this->mask.end(), pattern.begin()));
        return 0;
    }

    std::string open(std::string str, ull iterator, ull total_nums, ull count)
    {
        if ( !total_nums ) return str;

        auto before_star = [] (ull iterator_onstar) {return iterator_onstar - 1; };
        char sym = str[before_star(iterator)];
        index index_symbol = before_star(iterator);
        byte bt = this->bytes[before_star(iterator)];
        bool ms = this->mask[before_star(iterator)];

        str.erase(std::distance(mask_str.begin(), mask_str.begin() + before_star(iterator)), 2 + total_nums);
        this->bytes.erase(this->bytes.begin() + before_star(iterator));
        this->mask.erase(this->mask.begin() + before_star(iterator));

        this->bytes.insert(this->bytes.begin() + before_star(iterator), count, bt);
        this->mask.insert(this->mask.begin() + before_star(iterator), count, ms);
        str.insert(before_star(iterator), count, sym);

        return str;
    }

    std::pair<ull, ull> count_nums(ull current_iterator)
    {
        ull sum_nums, total_nums, i;
        sum_nums = total_nums = 0;
        i = 1;
        do {
            if ( this->mask_str[current_iterator + i] >= '0' && this->mask_str[current_iterator + i] <= '9' ) {
                sum_nums += this->mask_str[current_iterator + i] - '0'; // эта поебень больше не нужна, достаточно просто посчитать колво цифр и потянуть функу из стандартной либы
                total_nums++;
            } else break;
        } while ( i++ );
        current_iterator++;
        sum_nums = std::stoi(this->mask_str.substr(current_iterator, total_nums));
        return std::pair<ull, ull>(total_nums, sum_nums);
    }

    void parse()
    {
        for ( ull iterator = 0; iterator < this->mask_str.size(); iterator++ ) {
            switch ( this->mask_str[iterator] ) {
                case 'x': break;
                case '?': if ( this->mask_str[iterator + 1] == '*' ) break; this->bytes[iterator] = 0; this->mask[iterator] = false; break;
                case '*': {
                    auto tmp = count_nums(iterator);
                    this->mask_str = open(this->mask_str, iterator, tmp.first, tmp.second);
                    parse();

                }; break;
            }
        }
    }

public:
    std::vector<BYTE> bytes;
    std::vector<bool> mask; // 1 - defined, 0 - undefined
    std::string mask_str;
    Pattern(std::vector<BYTE> bytes, std::vector<bool> pattern)
    {
        this->bytes = bytes;
        this->mask = pattern;
        auto index = [=] (auto const &iterator) {
            return std::distance(this->mask.begin(), iterator);
        };

        if ( this->mask.size() == this->bytes.size() ) {
            for ( auto i = this->mask.begin(); i != this->mask.end(); ++i ) {
                if ( !(*i) ) {
                    this->bytes[index(i)] = 0b0;
                }
            }
        } else {
            throw("pattern size not matched with bytes size"s);
        }
        return;
    }

    Pattern(std::vector<BYTE> bytes)
    {
        this->bytes = bytes;
        this->mask = {};
        this->mask.resize(this->bytes.size(), 1);
        for ( size_t i = 0; i < this->bytes.size(); ++i ) if ( !(this->bytes[i]) ) this->mask[i] = 0b0; else;
        return;
    }

    Pattern(std::vector<BYTE> bytes, std::string str_mask)
    {
        this->bytes = bytes;
        this->mask.resize(this->bytes.size(), true);
        this->mask_str = str_mask;
        this->parse(); // TODO: пофиксить парсер
        return;
    }

    Pattern()
    {
        this->bytes = {};
        this->mask = {};
        return;
    }

    bool operator==(Pattern pattern2)
    {
        return (match(pattern2.bytes) && match(pattern2.mask));
    }

    std::wstringstream operator<<(Pattern)
    {
        std::wstringstream wss;
        for ( size_t i = 0; i < this->bytes.size(); ++i ) {
            wss << std::to_wstring(this->bytes[i])
                << std::wstring(L"\t->\t")
                << std::to_wstring(this->mask[i])
                << std::endl;
        }
        return wss;
    }

    BYTE &operator[](const ull index)
    {
        return this->bytes[index];
    }
};


struct WinapiHandles
{
    DWORD processid{ 0 };
    HWND window{ 0 };
    std::vector<HANDLE> handles{};
    std::vector<HMODULE> modules{};
};


class Offset
{
    std::vector<ADDRESS> addresses;
public:
    ull size()
    {
        return this->addresses.size();
    }

    ADDRESS &operator[](const ull index)
    {
        return this->addresses[index];
    }

    Offset operator+=(ADDRESS address)
    {
        this->addresses.push_back(address);
        return *this;
    }

    Offset operator+=(Offset offset)
    {
        for ( ull i = 0; i < offset.size(); ++i ) {
            this->addresses.push_back(i);
        }
        return *this;
    }
};


class RAM
{
public:
    ULONG dw_rights = PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    std::vector<std::pair<ADDRESS, ADDRESS>> unprotected_areas;
    std::vector<std::pair<ADDRESS, ADDRESS>> protected_areas;
    //ULONG dw_rights = PROCESS_VM_READ;
    const char *module_dll = "\0";
    MEMORY_BASIC_INFORMATION mbi;
    std::wstring process_name;
    std::wstring window_name;
    bool has_window = true;
    DWORD module_dll_base;
    HANDLE handles[32];
    HANDLE hProcess;
    DWORD dwProcId;
    HMODULE hMods;
    HWND hWindow;
    DWORD pid;
    HDC hDC;

    template <typename T>
    fastfunc T read(DWORD address);

    template <typename T>
    fastfunc void write(DWORD address, T value);

    template <typename T, size_t N>
    static auto countof(T(&array)[N]) ->  const size_t;

    template <typename T>
    void ScanMemoryArea(ADDRESS start, ADDRESS end);

    template <typename T>
    T SeqRead(DWORD address_base, std::vector<DWORD> offsets);

    template <typename T>
    T JumpMultiOffsets(T addr, DWORD offsets[], short &jumpCompleted);

    template<typename T>
    std::vector<DWORD> FindValue(T val);

    int CompareModules(wchar_t *str1, wchar_t *str2);//

    DWORD getModuleHandle(HMODULE hMods[]);

    std::pair<HANDLE, DWORD>GetModule(const wchar_t *modulename);

    DWORD getMultiModuleHandle();

    HANDLE getProcessHandle(const wchar_t *window_name);//

    DWORD GetProcessHandle(const wchar_t *process_name_exe);

    HWND getWindowHandle(const wchar_t *wch_window_name);

    HDC GetHDC();

    int read_bytes(LPCVOID addr, int num, void *buf);

    template<typename T>
    fastfunc T ReadMemoryArray(ADDRESS start_address, ADDRESS end_address);

    bool DataCompare(const BYTE *pData, const BYTE *pMask, const char *pszMask, size_t size);
    bool DataCompare(const BYTE *pData, const BYTE *pMask, const char *pszMask);

    DWORD FindPattern(DWORD start, DWORD size, CONST BYTE *sig, LPCSTR mask, size_t masksize);
    DWORD FindPattern(DWORD start, DWORD size, CONST BYTE *sig, LPCSTR mask);

    DWORD FindPatternArray(DWORD start, DWORD size, LPCSTR mask, int count, ...);
    DWORD FindPatternArray(DWORD start, DWORD size, std::string mask, ...);
    DWORD FindPatternArray(DWORD start, DWORD size, Pattern pattern);

    std::vector<DWORD> FindAllPatterns(DWORD startAddress, DWORD size, LPCSTR mask, int patterns_counter, std::vector<BYTE> sign);

    bool IsMemoryReadable(void *ptr, size_t byteCount);

    ADDRESS VerificatePattern(ADDRESS pattern2verificate, std::pair<ADDRESS, ADDRESS> range, LPCSTR mask, std::vector<BYTE> pattern_sign);

    void WaitProcess(std::wstring process_name, std::wstring window_name);
    void WaitProcess(std::wstring process_name);
    void WaitProcess();

    void GetWindow();
    HWND FindTopWindow();

    bool UnprotectMemory(ADDRESS address, size_t size);
    std::vector<byte> PartialRead(ADDRESS address, ull size);
    auto LocalizeProtected(ADDRESS start, ADDRESS end)
        ->std::vector<std::pair<ADDRESS, ADDRESS>>;
    auto SkipProtected(ADDRESS addr)
        -> const ADDRESS;
    auto NegativeProtected(std::pair<ADDRESS, ADDRESS> app_start_end)
        ->astype(RAM, LocalizeProtected(0, 0));
    auto IsInProtected(ADDRESS addr, std::pair<ADDRESS, ADDRESS> _protected)
        -> bool;
}ram;


class DllModule
{
    std::pair < HANDLE, DWORD >	module_base_size;
    std::vector < DWORD > offsets;
    const wchar_t *name;
    HANDLE handle_base;
    DWORD module_size;
    RAM *ram_ptr;
public:

    DllModule();
    DllModule(const wchar_t *name);
    DllModule(const wchar_t *name, RAM ram);
    DllModule(const wchar_t *name, Application app);

    const wchar_t *GetName();
    HANDLE GetBase();
    void SetBase(HANDLE val);
    void AddOffset(DWORD val);
    void AddOffsets(std::vector<DWORD> offsets);
    DWORD GetOffsset(USHORT index);
    std::vector<DWORD> GetOffssets();
    std::pair<HANDLE, DWORD> GetModuleBaseEnd();
    DWORD GetSize();

    void WithInstance(RAM *ram);
    void WithInstance(Application app);
    void WithInstance();

    void GetModule(std::wstring module_name);
};


template <typename DataType>
class Item
{
public:
    std::string id;
    DWORD baseAddress;
    std::vector<DWORD> addresses;
    std::vector<DataType> values;
};


class Rand
{
    std::random_device rd;
    std::mt19937::result_type seed;
    std::mt19937 gen;
public:
    Rand()
    {
        seed = rd() ^ (
            (std::mt19937::result_type)
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
                ).count() +
            (std::mt19937::result_type)
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()
                ).count());
    }

    fastfunc unsigned int randint(int min, int max)
    {
        std::mt19937 gen(seed);
        std::uniform_int_distribution<unsigned> distrib(min, max);
        return distrib(gen);
    }

    fastfunc std::string uuid()
    {
        const char v[] = "0123456789abcdef";
        const std::array<bool, 16> dash{ 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 };

        std::stringstream ss;
        std::for_each(
            dash.begin(),
            dash.end(),
            [=, &ss] (bool dash_value) {
                if ( dash_value ) {
                    ss << "-";
                }
                ss << v[randint(0, 17)];
                ss << v[randint(0, 17)];
            }
        );
        return ss.str();
    }
};


class Application
{
    SYSTEM_INFO system_info;
public:
    std::wstring name;
    RAM Ram;
    std::vector<DllModule> Dlls;

    Application()
    {
        memset(&this->system_info, 0, sizeof(system_info));
        GetSystemInfo(&system_info);

        WCHAR tmp[MAX_PATH];
        HMODULE hThis = NULL;
        GetModuleFileNameW(hThis, tmp, MAX_PATH);

        auto wtmp = std::wstring(tmp);
        this->name = std::wstring(wtmp.begin() + std::distance(wtmp.begin(), wtmp.begin() + wtmp.find_last_of(L'\\') + 1), wtmp.end());

        Ram.process_name = std::wstring(this->name);
        Ram.GetProcessHandle(this->name.c_str());
    }

    Application(LPCWSTR process_name) // Повинно закiнчуватися на .exe
    {
        this->name = std::wstring(process_name);

        Ram.process_name = std::wstring(process_name);
        memset(&this->system_info, 0, sizeof(system_info));
        GetSystemInfo(&system_info);

        Ram.GetProcessHandle(process_name);
        Ram.GetWindow();
        const auto addresses = this->MinMaxAddress();
        Ram.protected_areas = Ram.LocalizeProtected(addresses.first, addresses.second);
        Ram.unprotected_areas = Ram.NegativeProtected(addresses);
    }

    std::pair<ADDRESS, ADDRESS> MinMaxAddress()
    {
        return std::make_pair(reinterpret_cast<ADDRESS>(system_info.lpMinimumApplicationAddress), reinterpret_cast<ADDRESS>(system_info.lpMaximumApplicationAddress));
    }

    RAM *GetRamInstance()
    {
        return &this->Ram;
    }
};


template <typename T>
fastfunc T RAM::read(DWORD address)
{
    T _read;
    SIZE_T _bytesread = 0;
    ReadProcessMemory(hProcess, (LPCVOID)address, &_read, sizeof(T), &_bytesread);
    if ( !(_bytesread) || (sizeof(T) != _bytesread) ) {
        funcerror(std::format("Cannot read memory on address {}"s, address));
        if ( !hProcess ) {
            throw (std::exception("No have process handle. var: hProcess"));
        }
        DWORD stack = 0;
        _asm {
            mov stack, esp // || //DWORD PTR[ip];
        }
        std::cerr << "\tStack pointer address (hex): " << std::hex << stack << std::endl;
        //std::cerr << "\tTotal bytes read: " << _bytesread << std::endl;
    } else return _read;
}


template <typename T>
fastfunc void RAM::write(DWORD address, T value)
{
    WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(T), NULL);
}


template <typename T, size_t N>
static auto RAM::countof(T(&array)[N]) -> const size_t
{
    return N;
    //retutn std::size(T);
}


template <typename T>
void RAM::ScanMemoryArea(ADDRESS start, ADDRESS end)
{
    T _readbuf = 0;
    size_t _bytesread = 0;

    ReadProcessMemory(hProcess, start, &_readbuf, sizeof(T), &_bytesread);

    if ( _bytesread != 0 && start <= end )
        ScanMemoryArea(start += sizeof(T));
}


template <typename T>
T RAM::SeqRead(DWORD address_base, std::vector<DWORD> offsets)
{
    ADDRESS base_point = this->read<DWORD>(address_base);
    T out;
    USHORT counter = offsets.size();
    for ( auto i : offsets ) {
        counter--;
        if ( !counter ) {
            out = this->read<T>(base_point + i);
            return out;
        }
        base_point = this->read<DWORD>(base_point + i);
    }
}


template <typename T>
T RAM::JumpMultiOffsets(T addr, DWORD offsets[], short &jumpCompleted)
{
    DWORD buf[2];
    short amount_of_jumps = 0;
    LPDWORD *ptrToOffsets = &offsets;
    for ( int i = 0; ptrToOffsets != nullptr; i++ ) {
        amount_of_jumps++;
    }
    buf[0] = addr;
    short jumpCompl = 0;
    int data_size = sizeof(T);
    for ( int i = 0; amount_of_jumps != 0; i++ ) {
        buf[0] = read<DWORD>(buf[0] += offsets[i]);
        if ( buf[0] != 0 ) {
            jumpCompleted++;
        } else {
            std::cerr << "multiple jump error "; return 0;
        }
    }
    return buf[0];
}


template<typename T>
std::vector<DWORD> RAM::FindValue(T val)
{
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    std::vector<DWORD> addresses;
    auto start_ptr = system_info.lpMinimumApplicationAddress;
    auto end_ptr = system_info.lpMaximumApplicationAddress;
    uint32_t *current_ptr = reinterpret_cast<UINT32 *>(start_ptr);

    while ( current_ptr < end_ptr ) {
        MEMORY_BASIC_INFORMATION mbi;
        auto bytes = VirtualQueryEx(this->hProcess, current_ptr, &mbi, sizeof(mbi));
        if ( mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE ) {
            std::vector<uint8_t> read_buffer(mbi.RegionSize);
            SIZE_T read_byte;
            if ( ReadProcessMemory(this->hProcess, current_ptr, read_buffer.data(), mbi.RegionSize, &read_byte) == TRUE ) {
                T *current_page_ptr = reinterpret_cast<T *>(read_buffer.data());
                while ( (UINT8 *)current_page_ptr < read_buffer.data() + read_buffer.size() ) {
                    if ( *current_page_ptr == val ) {
                        addresses.push_back(reinterpret_cast<DWORD>(((reinterpret_cast<UINT8 *>(current_page_ptr)) - read_buffer.data()) + reinterpret_cast<UINT8 *>(mbi.BaseAddress)));
                    }
                    current_page_ptr = reinterpret_cast<T *>(reinterpret_cast<char *>(current_page_ptr) + 1);
                }
            }
        }
        current_ptr += mbi.RegionSize;
    }
    return addresses;
}


int RAM::CompareModules(wchar_t *str1, wchar_t *str2)
{
    return wstrcmp(str1, str2);
}


DWORD RAM::getModuleHandle(HMODULE hMods[])
{
    for ( ll i = 0; i < (pid / sizeof(HMODULE)); i++ ) {
        wchar_t szModName[MAX_PATH];
        if ( K32GetModuleFileNameExW(hProcess,
                                     hMods[i],
                                     szModName,
                                     sizeof(szModName) / sizeof(TCHAR)) ) {
            if ( !strcmp((char *)szModName, (char *)module_dll) ) {
                this->module_dll_base = (DWORD)hMods[i];
                return this->module_dll_base;
            }
        }
    }
}


std::pair<HANDLE, DWORD>RAM::GetModule(const wchar_t *modulename)
{
    HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE, dwProcId);
    if ( hModule == (HANDLE)-1 ) {
        std::wcerr
            << L"GetModule -> "s
            << L"Cant create snapshot from process"s
            << std::endl
            << GetLastError()
            << std::endl;
    }
    std::string_view error = "HANDLE GetModule() -> No have handle of process"s;

    MODULEENTRY32 mEntry;
    mEntry.dwSize = sizeof(mEntry);

    if ( (DWORD)hProcess == (DWORD)0x0 ) {
        std::cerr << error << std::endl;
        throw error;
        exit(0xAB0BA);
    }

    do {
        if ( !wstrcmp((wchar_t *)mEntry.szModule, (wchar_t *)modulename) ) {
            //Smodule module = { (DWORD)mEntry.hModule, mEntry.modBaseSize };
            return std::make_pair(mEntry.hModule, mEntry.modBaseSize);
        }
    } while ( Module32Next(hModule, &mEntry) );
    //std::wcerr << std::vformat(L"Find module {} failed\n", std::make_wformat_args(modulename));
    return std::make_pair((HANDLE)0, (DWORD)0);
}


DWORD RAM::getMultiModuleHandle()
{
    HMODULE hModsArray[32];
    K32EnumProcessModules(hProcess, hModsArray, sizeof(hModsArray), &pid);

    for ( int i = 0; i <= sizeof(hModsArray); i++ ) {
        std::cout << "loaded module from process\n";
        std::cout << hModsArray[i] << '\n';
        if ( (int)hModsArray[i] == 0xcccccccc )
            break;

    }
    Sleep(4000);
    return 0;
}


HANDLE RAM::getProcessHandle(const wchar_t *window_name)
{
    HWND hWnd;
    HDC hDC;
    hWnd = FindWindowW(0, window_name);
    if ( hWnd == 0 ) {
        printf("FindWindow failed, %08X\n", GetLastError());
        return NULL;
    } else {
        std::cout << "handle of window:\t" << hWnd << '\n';
    }
    GetWindowThreadProcessId(hWnd, &pid);
    std::cout << "process id is:\t" << pid << '\n';
    if ( pid == NULL ) {
        //std::cout << std::format("find process id failed by error {}\n", std::make_format_args(std::to_string(GetLastError())));
    }
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if ( hProcess == 0 ) {
        printf("OpenProcess failed, %08X\n", GetLastError());
        return NULL;
    } else {
        std::cout << "handle of process:\t" << hWnd << '\n';
    }
    hDC = GetDC(hWnd);
    HMODULE hModsArray[1024];
    HMODULE hMods;
    int i;
    if ( K32EnumProcessModules(hProcess, hModsArray, sizeof(hModsArray), &pid) == 0 ) {
        printf("enumprocessmodules failed, %08X\n", GetLastError());
    } else {
        getModuleHandle((HMODULE *)hModsArray);
    }

    return hProcess;
}


DWORD RAM::GetProcessHandle(const wchar_t *process_name_exe)
{
    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);
    do {
        if ( !wstrcmp((const wchar_t *)entry.szExeFile, (const wchar_t *)process_name_exe) ) {
            dwProcId = entry.th32ProcessID;
            CloseHandle(handle);
            hProcess = OpenProcess(dw_rights, false, dwProcId);
            return (DWORD)hProcess;
        }
    } while ( Process32Next(handle, &entry) );
    return (DWORD)false;
}


HWND RAM::getWindowHandle(const wchar_t *wch_window_name)
{
    if ( lstrlenW(wch_window_name) == NULL ) {
        std::cerr << "HWND getWindowHandle() -> no have window name"s << std::endl;
    }
    hWindow = FindWindowW(0, wch_window_name);
    if ( !hWindow ) has_window = false;
    return hWindow;
}


HDC RAM::GetHDC()
{
    if ( hWindow != NULL && has_window ) {
        this->hDC = GetWindowDC(hWindow);
        if ( this->hDC != NULL ) {
            return this->hDC;
        }
        std::cerr << "invalid hdc handle"s << std::endl;
        throw "invalid hdc handle"s;
    }
    std::cout << "This app have no visible windows"s << std::endl;
}


int RAM::read_bytes(LPCVOID addr, int num, void *buf)
{
    SIZE_T sz = 0;
    int r = ReadProcessMemory(hProcess, addr, buf, num, &sz);
    if ( r == 0 || sz == 0 ) {
        printf("RPM error, %08X\n", "errorStatus:t", GetLastError(), "\tbyteSIze:", sz, "\tr size:", r);
        return 0;
    }
    return 1;
}


template<typename T>
fastfunc T RAM::ReadMemoryArray(ADDRESS start_address, ADDRESS end_address)
{
    end_address -= end_address % sizeof(T);
    T *buf = new T[end_address - start_address / sizeof(T)];
    for ( ; start_address <= end_address; start_address++ )
        read_bytes((LPCVOID)start_address, sizeof(T), &buf);
    return buf;
}


fastfunc bool RAM::DataCompare(const BYTE *pData, const BYTE *pMask, const char *pszMask)
{
    for ( ; *pszMask; ++pszMask, ++pData, ++pMask ) {
        if ( *pszMask == 'x' && *pData != *pMask ) {
            return false;
        }
    }
    return (*pszMask == NULL);
}


fastfunc bool RAM::DataCompare(const BYTE *readed_data, const BYTE *signature, const char *mask, size_t size)
{
    size_t i = 0;
    for ( ; i < size; ++i, ++readed_data ) {
        if ( mask[i] == 'x' && *readed_data != signature[i] ) {
            return false;
        }
    }
    return (i != NULL);
}


DWORD RAM::FindPattern(DWORD start, DWORD size, CONST BYTE *sig, LPCSTR mask, size_t masksize)
{
    if ( !size ) throw std::invalid_argument("zero bytes to compare");

    BYTE *data = new BYTE[size + 1];
    std::fill_n(data, size + 1, 0);
    SIZE_T bytesread = NULL;

    if ( !this->IsMemoryReadable((void *)start, size) ) {
        // TODO
        // FIXME
        //this->FindPattern(start + sizeof DWORD, size - sizeof DWORD, sig, mask, masksize);
        //std::cerr << "cannot read memory" << ": " << "Memory block is not readable by protect" << std::endl;
    }

    ReadProcessMemory(hProcess, (LPCVOID)start, data, size, &bytesread);
    if ( bytesread <= 0 ) {
        //std::cerr << std::format("Cannot read memory: {} error\n"s, std::to_string(GetLastError()));
        //throw std::invalid_argument("FindPattern -> cannot read memory");
    }

    for ( DWORD i = 0; i < size; i++ ) {
        if ( DataCompare((CONST BYTE *)(data + i), (CONST BYTE *)sig, mask, masksize) ) {
            delete[](data);
            return start + i;
        }
    }

    delete[](data);
    return NULL;
}


DWORD RAM::FindPattern(DWORD start, DWORD size, CONST BYTE *sig, LPCSTR mask)
{
    if ( !size ) throw "zero bytes to compare"s;
    if ( !this->IsMemoryReadable((void *)start, size) ) {
        //funcerror("Cannot read memory: Memory block is not readable by protect");
        //this->UnprotectMemory(start, size);
    }

    BYTE *data = new BYTE[size];
    SIZE_T bytesread = NULL;

    std::fill_n(data, size, 0);
    //ReadProcessMemory(hProcess, (LPCVOID)start, data, size, &bytesread);

    ull _current = start;
    auto out = this->PartialRead(start, size);
    for ( ull i = 0; i < out.size(); ++i ) {
        data[i] = out[i];
    }

    for ( DWORD i = 0; i < size; i++ ) {
        if ( DataCompare((CONST BYTE *)(data + i), (CONST BYTE *)sig, mask) ) {
            delete[](data);
            return start + i;
        }
    }

    delete[](data);
    return NULL;
}


DWORD RAM::FindPatternArray(DWORD start, DWORD size, LPCSTR mask, int count, ...)
{
    byte *sig = new byte[count + 1];
    va_list ap;
    va_start(ap, count);
    for ( int i = 0; i < count; i++ ) {
        char read = va_arg(ap, char);
        sig[i] = read;

    }
    va_end(ap);
    sig[count] = '\0';
    return FindPattern(start, size, sig, mask, count);
}


DWORD RAM::FindPatternArray(DWORD start, DWORD size, std::string mask, ...)
{
    size_t count = mask.size();
    byte *sig = new byte[count + 1];
    va_list ap;
    va_start(ap, count);
    for ( int i = 0; i < count; i++ ) {
        char read = va_arg(ap, char);
        sig[i] = read;

    }
    va_end(ap);
    sig[count] = '\0';
    return FindPattern(start, size, sig, mask.c_str(), mask.size());
}


DWORD RAM::FindPatternArray(DWORD start, DWORD size, Pattern pattern)
{
    if ( !this->IsMemoryReadable((void *)start, 1) ) {
        throw;
    }
    byte *sig = new byte[pattern.bytes.size() + 1];
    for ( size_t i = 0; i < pattern.bytes.size(); ++i )
        sig[i] = pattern.bytes[i];
    sig[pattern.bytes.size()] = '\0';

    LPCSTR mask = pattern.mask_str.c_str();
    return FindPattern(start, size, sig, mask, pattern.bytes.size());
}


std::vector<DWORD> RAM::FindAllPatterns(DWORD startAddress, DWORD end_address, LPCSTR mask, int patterns_counter, std::vector<BYTE> sign)
{
    auto count = sign.size();
    byte *sig = new byte[count + 1];
    for ( int i = 0; i < count; i++ ) {
        char read = sign[i];
        sig[i] = read;

    }
    sig[count] = '\0';

    std::vector<DWORD> patern_addresses;
    DWORD checksize = 0xFF;
    for ( int i = 0; patern_addresses.size() < patterns_counter; ++i ) {
        for ( DWORD64 currentaddress = startAddress; currentaddress < end_address;) {
            auto finded = FindPattern(currentaddress, checksize, sig, mask);

            if ( startAddress < end_address && finded < end_address && finded ) {
                patern_addresses.push_back(finded);
                currentaddress = patern_addresses[patern_addresses.size() - 1] + 1;
                continue;
            }
            if ( currentaddress > end_address )
                throw(1);
            currentaddress += checksize;
        }
        delete[](sig);
        if ( patern_addresses.size() )
            return patern_addresses;
        else
            throw std::exception("No addresses found");
    }
    return patern_addresses;
}

/// <summary>
/// Чекает кусок памяти со старта и до заданного кол-ва байт
/// </summary>
/// <param name="ptr">: Адрес начала блока памяти, который надо прочекать</param>
/// <param name="byteCount">: Кол-во байт, которые надо прочекать</param>
/// <returns></returns>
bool RAM::IsMemoryReadable(void *ptr, size_t byteCount)
{
    MEMORY_BASIC_INFORMATION temp_mbi;
    if ( VirtualQuery(ptr, &temp_mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0 )
        return false;

    if ( temp_mbi.State != MEM_COMMIT )
        return false;

    if ( temp_mbi.Protect == PAGE_NOACCESS || temp_mbi.Protect == PAGE_EXECUTE )
        return false;

    size_t blockOffset = (size_t)((char *)ptr - (char *)temp_mbi.AllocationBase);
    size_t blockBytesPostPtr = temp_mbi.RegionSize - blockOffset;

    /*if ( blockBytesPostPtr < byteCount )
        return this->IsMemoryReadable(
            (char*)ptr + blockBytesPostPtr,
            byteCount - blockBytesPostPtr);*/

    return true;
}

/// <summary>
/// Finds byte pattern that must be near with other pattern
/// </summary>
/// <param name="pattern2verificate"></param>
/// <param name="range"></param>
/// <param name="mask"></param>
/// <param name="pattern_sign"></param>
/// <returns></returns>
ADDRESS RAM::VerificatePattern(ADDRESS pattern2verificate, std::pair<ADDRESS, ADDRESS> range, LPCSTR mask, std::vector<BYTE> pattern_sign)
// Эта штука должна находить байтовый паттерн, который может находиться только рядом с нужным адресом
// pattern2verificate - адрес, от которого искать
// range - область допустимых адресов вниз и вверх относительно адреса паттерна, который нужно проверить(как далеко искать)
// pattern_sign - массив байт, при нахождении которого в определенной области, можно быть уверенным, что паттерн тот, который нужен
// паттерн для верификации должен отличаться от верифицируемого паттерна
{
    auto count = pattern_sign.size();
    byte *sig = new byte[count + 1];
    for ( int i = 0; i < count; i++ ) {
        char read = pattern_sign[i];
        sig[i] = read;

    }
    sig[count] = '\0';
    auto currentaddress = pattern2verificate - range.first; // нижний предел поиска
    auto checksize = range.first + range.second;
    ADDRESS finded = FindPattern(currentaddress, checksize, sig, mask);
    return  finded - pattern2verificate;
    // возвращает дистанцию между найденым папттерном и верифицируемым
}


void RAM::WaitProcess(std::wstring process_name, std::wstring window_name)
{
    for ( ;; Sleep(1000) ) {
        if ( process_name != L"" && window_name != L"" ) {
            if ( this->GetProcessHandle(process_name.c_str()) && this->getWindowHandle(window_name.c_str()) )
                return;
        } else {
            if ( this->process_name == L"" || this->window_name == L"" )
                throw(0xAB0BA);
            process_name = this->process_name;
            window_name = this->window_name;
        }
    }
}


void RAM::WaitProcess(std::wstring process_name)
{
    for ( ;; Sleep(1000) ) {
        if ( process_name != L"" ) {
            if ( this->GetProcessHandle(process_name.c_str()) )
                return;
        } else {
            if ( this->process_name == L"" )
                throw(0xAB0BA);
            process_name = this->process_name;
        }

    }
}


void RAM::WaitProcess()
{
    if ( this->process_name == L"" || this->window_name == L"" )
        throw(0xAB0BA);
    for ( ;; Sleep(1000) )
        if ( this->GetProcessHandle(this->process_name.c_str()) ) {
            this->GetWindow();
            return;
        }
}


void RAM::GetWindow()
{
    if ( this->dwProcId ) {
        this->hWindow = this->FindTopWindow();
        this->GetHDC();
    } else {
        this->hWindow = this->getWindowHandle(this->window_name.c_str());
    }
}


HWND RAM::FindTopWindow()
{
    if ( !this->dwProcId )
        throw std::exception("FindTopWindow -> Cannot get process id");
    DWORD pid = this->dwProcId;
    std::pair<HWND, DWORD> params = { 0, pid };

    BOOL bResult = EnumWindows(
        [] (HWND hwnd, LPARAM lParam) -> BOOL {
            auto pParams = (std::pair<HWND, DWORD>*)(lParam);

            DWORD processId;
            if ( GetWindowThreadProcessId(hwnd, &processId) && processId == pParams->second ) {
                SetLastError(-1);
                pParams->first = hwnd;
                return false;
            }

            return true; },
        (LPARAM)&params);

    if ( !bResult && GetLastError() == -1 && params.first ) {
        return params.first;
    }

    return 0;
}


bool RAM::UnprotectMemory(ADDRESS address, size_t size)
{
    // В идеале - вызвать отделённый процесс, им открыть процесс таргета с правами PROCESS_VM_OPERATION и репротектнуть NOACCESS страницу
    // Но это в идеале, а пока...
    DWORD newprotect = PAGE_EXECUTE | PAGE_READWRITE;
    if ( !VirtualProtect(reinterpret_cast<LPVOID>(address), size, newprotect, nullptr) ) {
        funcerror("Cannot unprotect memory");
        return false;
        // всегда падает с кодом 998
        // сука)0))
    }
    return true;
}



DllModule::DllModule()
{
    offsets.clear();
    handle_base = 0x0;
    module_size = 0x0;
}


DllModule::DllModule(const wchar_t *name)
{
    offsets.clear();
    this->name = name;
    module_base_size = ram_ptr->GetModule(this->name);
    handle_base = module_base_size.first;
    module_size = module_base_size.second;
}


DllModule::DllModule(const wchar_t *name, RAM ram)
{
    this->ram_ptr = &ram;
    offsets.clear();
    this->name = name;
    module_base_size = ram_ptr->GetModule(this->name);
    handle_base = module_base_size.first;
    module_size = module_base_size.second;
    return;
}


DllModule::DllModule(const wchar_t *name, Application app)
{
    *this = DllModule(name);
    this->ram_ptr = app.GetRamInstance();
}


const wchar_t *DllModule::GetName()
{
    return this->name;
}


HANDLE DllModule::GetBase()
{
    return handle_base;
}


void DllModule::SetBase(HANDLE val)
{
    handle_base = val;
}


void DllModule::AddOffset(DWORD val)
{
    offsets.push_back((DWORD)val);
}


void DllModule::AddOffsets(std::vector<DWORD> offsets)
{
    for ( auto i : offsets )
        this->offsets.push_back(i);
}


DWORD DllModule::GetOffsset(USHORT index)
{
    return offsets[index];
}


std::vector<DWORD> DllModule::GetOffssets()
{
    return offsets;
}


std::pair<HANDLE, DWORD> DllModule::GetModuleBaseEnd()
{
    return this->module_base_size;
}


DWORD DllModule::GetSize()
{
    return this->module_base_size.second;
}


void DllModule::WithInstance(RAM *ram)
{
    this->ram_ptr = ram;
}


void DllModule::WithInstance(Application app)
{
    this->ram_ptr = &app.Ram;
}


void DllModule::GetModule(std::wstring module_name)
{
    offsets.clear();
    this->name = module_name.c_str();
    module_base_size = ram_ptr->GetModule(this->name);
    handle_base = module_base_size.first;
    module_size = module_base_size.second;
}


Application this_application = Application();


std::vector<byte> RAM::PartialRead(ADDRESS address, ull size)
{
    std::vector<byte> out;
    ADDRESS _current = address;
    while ( _current < address + size ) {
        out.push_back(this->read<byte>(_current));
        _current += sizeof byte;
    }
    return out;
}

struct CEbytearr
{
    std::string byte_array;
    CEbytearr(std::string ba);
    std::vector<byte> as_bytes();
};

CEbytearr::CEbytearr(std::string ba)
{
    std::for_each(ba.begin(), ba.end(), [this] (char ch) {this->byte_array += (char)std::tolower((int)ch); });
    const static byte bytes[] = "0123456789abcdef";
    for ( ull i = 0; i < this->byte_array.size(); i % 3 == 0 || !i ? i += 1 : i += 2 ) { // каждый 3 , начиная с 1, пропрыгивает пробел
        bool is_in = false;
        for ( ull j = 0; j < RAM::countof(bytes); ++j ) {
            if ( this->byte_array[i] == bytes[j] ) {
                is_in = !is_in;
            }
        }
        if ( !is_in ) {
            throw;
        }
    }
}

std::vector<byte> CEbytearr::as_bytes()
{
    std::vector<char> buf;
    for ( auto i : this->byte_array ) {
        i != ' ' ? buf.push_back(i) : (void)nullptr;
    }
//std::erase(this->ba, ' ');
    std::vector<byte> out;
    for ( auto i = buf.begin(); i < buf.end() - 1; i += 2 ) {
        out.push_back(std::strtol(new char[3]{ *i, *(i + 1) }, NULL, 16));
    }
    return out;
}

auto RAM::LocalizeProtected(ADDRESS start, ADDRESS end) -> std::vector<std::pair<ADDRESS, ADDRESS>>
{
    astype(RAM, LocalizeProtected(0, 0)) out
    {};
    if ( !start && !end ) return out;
    const u32 step = 1024;
    bool is_protected = false;
    while ( start <= end ) {
        if ( !this->IsMemoryReadable((void *)start, 1) ) {
            if ( !is_protected ) {
                out.push_back(std::make_pair(start, (ADDRESS)(start + step)));
            }
            is_protected = true;
        } else {
            if ( is_protected ) {
                (out.end() - 1)->second = start;
            }
            is_protected = false;
        }
        start += step;
    }
    return out;
}


auto RAM::SkipProtected(ADDRESS addr) -> const ADDRESS
{
    auto isInProtected = [=] (ADDRESS addr, std::pair<ADDRESS, ADDRESS> _protected) {
        if ( addr >= _protected.first && addr <= _protected.second ) {
            return true;
        }
        return false;
    };
    for ( auto i : this->protected_areas ) {
        if ( isInProtected(addr, i) ) {
            return i.second + 1024;
        }
    }
}

auto RAM::NegativeProtected(std::pair<ADDRESS, ADDRESS> app_start_end)->astype(RAM, LocalizeProtected(0, 0))
{
    astype(RAM, NegativeProtected({ 0,0 })) out
    {};
    ADDRESS current = app_start_end.first;
    for ( const auto i : this->protected_areas ) {
        if ( this->IsInProtected(current, i) ) {
            current = i.second + 1;
            continue;
        }
        out.push_back({ current, i.first - 1024 });
        current = i.second + 1024;
    }
    return out;
}


auto RAM::IsInProtected(ADDRESS addr, std::pair<ADDRESS, ADDRESS> _protected) -> bool
{
    if ( addr >= _protected.first && addr <= _protected.second ) {
        return true;
    }
    return false;
}