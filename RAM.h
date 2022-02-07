#pragma once

#include <Windows.h>
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
#include <fstream>
#include <sstream>
#include <iomanip>
#include <array>
#include <utility>

using namespace std::string_literals;

typedef long long ll;
typedef unsigned long long ull;

typedef size_t ADDRESS;
typedef size_t index;
typedef std::wstring wstr;
typedef unsigned char byte;

#define fastfunc __forceinline


#ifndef UNICODE
#define _T(x) L##x
#endif // UNICODE


int wstrcmp(const wchar_t* str1, const wchar_t* str2);
byte new_wstrcmp(const wchar_t* str1, const wchar_t* str2);



int wstrcmp(const wchar_t* str1, const wchar_t* str2)
{
    return std::wstring(str1).compare(std::wstring(str2));
}

byte new_wstrcmp(const wchar_t* str1, const wchar_t* str2)
{
    byte not_lenght_equal = 0xFF;
    byte not_symbol_equal = 0xFE;
    byte equal = 0x0;
    if ( lstrlenW(str1) != lstrlenW(str2) )
    {
        return not_lenght_equal;
    }
    for ( byte i = lstrlenW(str1); i > 0; --i )
    {
        if ( str1[i] != str2[i] )
        {
            return not_symbol_equal;
        }
    }
    return equal;
}


class Pattern
{
    bool match(std::vector<BYTE, std::allocator<BYTE>> bytes)
    {
        if ( this->bytes.size() == bytes.size() ) return static_cast<bool>( std::equal(this->bytes.begin(), this->bytes.end(), bytes.begin()) );
        return 0;
    }

    bool match(std::vector<bool, std::allocator<bool>> pattern)
    {
        if ( this->mask.size() == pattern.size() ) return static_cast<bool>( std::equal(this->mask.begin(), this->mask.end(), pattern.begin()) );
        return 0;
    }

    std::string open(std::string str, ull iterator, ull total_nums, ull count)
    {
        if ( !total_nums ) return str;
        auto before_star = [](ull iterator_onstar){return iterator_onstar-1;};
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
        ull sum_nums, total_nums, i; sum_nums = total_nums = 0; i = 1;
        do
        {
            if ( this->mask_str[current_iterator + i] >= '0' and this->mask_str[current_iterator + i] <= '9' )
            {
                sum_nums += this->mask_str[current_iterator + i] - '0';
                total_nums++;
            }
            else break;
        }
        while ( i++ );
        current_iterator++;
        std::string num_slice = this->mask_str.substr(current_iterator, total_nums);
        sum_nums = std::stoi(num_slice);
        return std::pair<ull,ull>(total_nums, sum_nums);
    }

    void parse()
    {
        for ( ull iterator = 0; iterator < this->mask_str.size(); iterator++ )
        {
            switch ( this->mask_str[iterator] )
            {
                case 'x': break;
                case '?': if(this->mask_str[iterator + 1] == '*') break; this->bytes[iterator] = 0; this->mask[iterator] = false; break;
                case '*':
                {
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
        auto index = [=](auto const& iterator)
        {
            return std::distance(this->mask.begin(), iterator);
        };
        if ( this->mask.size() == this->bytes.size() ) for ( auto i = this->mask.begin(); i != this->mask.end(); ++i ) if ( !( *i ) ) this->bytes[index(i)] = 0b0; else;
        else throw( "pattern size not matched with bytes size"s );
        return;
    }

    Pattern(std::vector<BYTE> bytes)
    {
        this->bytes = bytes;
        this->mask = {};
        this->mask.resize(this->bytes.size(), 1);
        for ( size_t i = 0; i < this->bytes.size(); ++i ) if ( !( this->bytes[i] ) ) this->mask[i] = 0b0; else;
        return;
    }

    Pattern(std::vector<BYTE> bytes, std::string str_mask)
    {
        this->bytes = bytes;
        this->mask.resize(this->bytes.size(), true);
        this->mask_str = str_mask;
        this->parse();
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
        return ( match(pattern2.bytes) && match(pattern2.mask) );
    }

    std::wstring operator<<(Pattern)
    {
        std::wstring tmp;
        std::wstringstream wss;
        for ( size_t i = 0; i < this->bytes.size(); ++i )
        {
            wss << std::to_wstring(this->bytes[i])
                << std::wstring(L"\t->\t")
                << std::to_wstring(this->mask[i])
                << std::endl;

            tmp += ( std::to_wstring(this->bytes[i])
                    + std::wstring(L"\t->\t")
                    + std::to_wstring(this->mask[i])
                    + std::wstring(L"\n") );

        }
        return wss.str();
    }
};


struct WinapiHandles
{
    HWND window{0};
    std::vector<HANDLE> handles{};
    std::vector<DWORD> processid{};
    std::vector<HMODULE> modules{};
};

class Offset
{
    std::vector<ADDRESS> addresses;
};

class RAM
{
public:
    ULONG dw_rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    const char* module_dll = "\0";
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
    fastfunc T read(HANDLE address);

    template <typename T>
    fastfunc void write(HANDLE address, T value);

    template <typename T, size_t N>
    size_t countof(T(&array)[N]);

    template <typename T>
    void ScanMemoryArea(ADDRESS start, ADDRESS end);

    template <typename T>
    T SeqRead(DWORD address_base, std::vector<DWORD> offsets);

    template <typename T>
    void PrintArray(T arr[]);

    template <typename T>
    T JumpMultiOffsets(T addr, DWORD offsets[], short& jumpCompleted);

    template<typename T>
    std::vector<DWORD> FindValue(T val);

    int CompareModules(wchar_t* str1, wchar_t* str2);//

    DWORD getModuleHandle(HMODULE hMods[]);

    std::pair<HANDLE, DWORD>GetModule(const wchar_t* modulename);

    DWORD getMultiModuleHandle();

    HANDLE getProcessHandle(const wchar_t* window_name);//

    DWORD GetProcessHandle(const wchar_t* process_name_exe);

    HWND getWindowHandle(const wchar_t* wch_window_name);

    HDC GetHDC();

    int read_bytes(LPCVOID addr, int num, void* buf);

    template<typename T>
    fastfunc T ReadMemoryArray(ADDRESS start_address, ADDRESS end_address);

    bool DataCompare(const BYTE* pData, const BYTE* pMask, const char* pszMask, size_t size);
    bool DataCompare(const BYTE* pData, const BYTE* pMask, const char* pszMask);

    DWORD FindPattern(DWORD start, DWORD size, CONST BYTE* sig, LPCSTR mask, size_t masksize);
    DWORD FindPattern(DWORD start, DWORD size, CONST BYTE* sig, LPCSTR mask);

    DWORD FindPatternArray(DWORD start, DWORD size, LPCSTR mask, int count, ...);//find pattern array in address space of process
    DWORD FindPatternArray(DWORD start, DWORD size, std::string mask, ...);
    DWORD FindPatternArray(DWORD start, DWORD size, Pattern pattern);

    std::vector<DWORD> FindAllPatterns(DWORD startAddress, DWORD size, LPCSTR mask, int patterns_counter, std::vector<BYTE> sign);

    bool IsMemoryReadable(void* ptr, size_t byteCount);

    ADDRESS VerificatePattern(ADDRESS pattern2verificate, std::pair<ADDRESS, ADDRESS> range, LPCSTR mask, std::vector<BYTE> pattern_sign);

    void WaitProcess(std::wstring process_name, std::wstring window_name);
    void WaitProcess(std::wstring process_name);
    void WaitProcess();

    void GetWindow();
    HWND FindTopWindow();
}ram;


class DllModule
{
    std::pair < HANDLE, DWORD >	module_base_size;
    std::vector < DWORD > offsets;
    const wchar_t* name;
    HANDLE handle_base;
    DWORD module_size;
    RAM *ram_ptr;
public:

    DllModule();
    DllModule(const wchar_t* name);
    DllModule(const wchar_t* name, RAM ram);

    const wchar_t* GetName();
    HANDLE GetBase();
    void SetBase(HANDLE val);
    void AddOffset(DWORD val);
    void AddOffsets(std::vector<DWORD> offsets);
    DWORD GetOffsset(USHORT index);
    std::vector<DWORD> GetOffssets();
    std::pair<HANDLE, DWORD> GetModuleBaseEnd();
    DWORD GetSize();
    void WithInstance(RAM *ram);
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
            ).count() );

    }

    __forceinline unsigned int randint(int min, int max)
    {
        std::mt19937 gen(seed);
        std::uniform_int_distribution<unsigned> distrib(min, max);
        return distrib(gen);
    }
};


template<typename T>
class Iterator
{
    T val;
public:
    Iterator(size_t init = 0) : val(init)
    { }
    T next()
    {
        return ++val;
    }
    T prev()
    {
        return --val >= 0 ? val : throw( "iterator < 0"s );
    }
    T get()
    {
        return val;
    }
};


template <typename T>
fastfunc T RAM::read(HANDLE  address)
{
    static T _read;
    static size_t _bytesread = 0;
    ReadProcessMemory(hProcess, (LPCVOID)address, &_read, sizeof(T), &_bytesread);
    if ( !( _bytesread ) || ( sizeof(T) != _bytesread ) ) std::cerr << "read -> cannot read memory\n";
    else return _read;
}


template <typename T>
fastfunc void RAM::write(HANDLE address, T value)
{
    WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(T), NULL);
}


template <typename T, size_t N>
size_t RAM::countof(T(&array)[N])
{
    return N;
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
    for ( auto i : offsets )
    {
        counter--;
        if ( !counter )
        {
            out = this->read<T>(base_point + i);
            return out;
        }
        base_point = this->read<DWORD>(base_point + i);
    }
}


template <typename T>
void RAM::PrintArray(T arr[])
{
    for ( auto i : arr ) std::cout << i << '\n';
}


template <typename T>
T RAM::JumpMultiOffsets(T addr, DWORD offsets[], short& jumpCompleted)
{
    DWORD buf[2];
    short amount_of_jumps = 0;
    LPDWORD* ptrToOffsets = &offsets;
    for ( int i = 0; ptrToOffsets != nullptr; i++ )
    {
        amount_of_jumps++;
    }
    buf[0] = addr;
    short jumpCompl = 0;
    int data_size = sizeof(T);
    for ( int i = 0; amount_of_jumps != 0; i++ )
    {
        buf[0] = read<DWORD>(buf[0] += offsets[i]);
        if ( buf[0] != 0 )
        {
            jumpCompleted++;
        }
        else
        {
            std::cout << "multiple jump error "; return 0;
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
    uint32_t* current_ptr = reinterpret_cast<UINT32*>( start_ptr );

    while ( current_ptr < end_ptr )
    {
        MEMORY_BASIC_INFORMATION mbi;
        auto bytes = VirtualQueryEx(this->hProcess, current_ptr, &mbi, sizeof(mbi));
        if ( mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE )
        {
            std::vector<uint8_t> read_buffer(mbi.RegionSize);
            SIZE_T read_byte;
            if ( ReadProcessMemory(this->hProcess, current_ptr, read_buffer.data(), mbi.RegionSize, &read_byte) == TRUE )
            {
                T* current_page_ptr = reinterpret_cast<T*>( read_buffer.data() );
                while ( (UINT8*)current_page_ptr < read_buffer.data() + read_buffer.size() )
                {
                    if ( *current_page_ptr == val )
                    {
                        addresses.push_back(reinterpret_cast<DWORD>( ( ( reinterpret_cast<UINT8*>( current_page_ptr ) ) - read_buffer.data() ) + reinterpret_cast<UINT8*>( mbi.BaseAddress ) ));
                    }
                    current_page_ptr = reinterpret_cast<T*>( reinterpret_cast<char*>( current_page_ptr ) + 1 );
                }
            }
        }
        current_ptr += mbi.RegionSize;
    }
    return addresses;
}


int RAM::CompareModules(wchar_t* str1, wchar_t* str2)
{
    unsigned long str1_symbols = 0;
    unsigned long str2_symbols = 0;
    int counter = 0;
    for ( int i = 0; str1[i] != '\0'; i++ )
    {
        str1_symbols++;
    }
    for ( int j = 0; str2[j] != '\0'; j++ )
    {
        str2_symbols++;
    }
    for ( ; str2_symbols != 0; str2_symbols-- )
    {
        if ( str1[str1_symbols] == str2[str2_symbols] )
        {
        }
        else
        {
            counter++;
        }
        str1_symbols--;
    }

    return counter;
}


DWORD RAM::getModuleHandle(HMODULE hMods[])
{
    unsigned i;
    for ( i = 0; i < ( pid / sizeof(HMODULE) ); i++ )
    {
        wchar_t szModName[MAX_PATH];
        if ( K32GetModuleFileNameExW(hProcess, hMods[i], szModName,
            sizeof(szModName) / sizeof(TCHAR)) )
        {
            if ( strcmp((char*)szModName, (char*)module_dll) == NULL )
            {
                if ( CompareModules((wchar_t*)szModName, (wchar_t*)module_dll) == 0 )
                {
                    printf("client.dll base: %08X\n", hMods[i]);
                    module_dll_base = (DWORD)hMods[i];
                    return module_dll_base;
                }
                continue;
            }
        }
    }
}


std::pair<HANDLE, DWORD>RAM::GetModule(const wchar_t* modulename)
{

    HANDLE h_module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcId);
    std::string_view error = "HANDLE GetModule() -> No have handle of process"s;

    MODULEENTRY32 mEntry;
    mEntry.dwSize = sizeof(mEntry);

    if ( (DWORD)hProcess == (DWORD)0x0 )
    {
        std::cerr << error << std::endl;
        throw error;
        exit(0xAB0BA);
    }

    do
    {
        if ( !new_wstrcmp((wchar_t*)mEntry.szModule, (wchar_t*)modulename) )
        {
            //Smodule module = { (DWORD)mEntry.hModule, mEntry.modBaseSize };
            return std::make_pair(mEntry.hModule, mEntry.modBaseSize);

        }
    } while ( Module32Next(h_module, &mEntry) );
    std::wcout << L"Find " << modulename << L" module failed" << std::endl;
    return std::make_pair((HANDLE)0, (DWORD)0);
}


DWORD RAM::getMultiModuleHandle()
{
    HMODULE hModsArray[32];
    K32EnumProcessModules(hProcess, hModsArray, sizeof(hModsArray), &pid);

    for ( int i = 0; i <= sizeof(hModsArray); i++ )
    {
        std::cout << "loaded module from process\n";
        std::cout << hModsArray[i] << '\n';
        if ( (int)hModsArray[i] == 0xcccccccc )
            break;

    }
    Sleep(4000);
    return 0;
}


HANDLE RAM::getProcessHandle(const wchar_t* window_name)
{
    HWND hWnd;
    HDC hDC;
    hWnd = FindWindowW(0, window_name);
    if ( hWnd == 0 )
    {
        printf("FindWindow failed, %08X\n", GetLastError());
        return NULL;
    }
    else
    {
        std::cout << "handle of window:\t" << hWnd << '\n';
    }
    GetWindowThreadProcessId(hWnd, &pid);
    std::cout << "process id is:\t" << pid << '\n';
    if ( pid == NULL )
    {
        std::cout << "find process id failed\n"; GetLastError();
    }
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if ( hProcess == 0 )
    {
        printf("OpenProcess failed, %08X\n", GetLastError());
        return NULL;
    }
    else
    {
        std::cout << "handle of process:\t" << hWnd << '\n';
    }
    hDC = GetDC(hWnd);
    HMODULE hModsArray[1024];
    HMODULE hMods;
    int i;
    if ( K32EnumProcessModules(hProcess, hModsArray, sizeof(hModsArray), &pid) == 0 )
    {
        printf("enumprocessmodules failed, %08X\n", GetLastError());
    }
    else
    {
        getModuleHandle((HMODULE*)hModsArray);
    }

    return hProcess;
}


DWORD RAM::GetProcessHandle(const wchar_t* process_name_exe)
{
    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);
    do
    {
        if ( !new_wstrcmp((const wchar_t*)entry.szExeFile, (const wchar_t*)process_name_exe) )
        {
            dwProcId = entry.th32ProcessID;
            CloseHandle(handle);
            hProcess = OpenProcess(dw_rights, false, dwProcId);
            return (DWORD)hProcess;
        }
    } while ( Process32Next(handle, &entry) );
    return (DWORD)false;
}


HWND RAM::getWindowHandle(const wchar_t* wch_window_name)
{
    if ( lstrlenW(wch_window_name) == NULL )
    {
        std::cerr << "HWND getWindowHandle() -> no have window name" << std::endl;
    }
    hWindow = FindWindowW(0, wch_window_name);
    if ( !hWindow ) has_window = false;
    return hWindow;
}


HDC RAM::GetHDC()
{
    if ( hWindow != NULL && has_window )
    {
        this->hDC = GetWindowDC(hWindow);
        if ( this->hDC != NULL )
        {
            return this->hDC;
        }
        std::cout << "invalid hdc handle" << std::endl;
        throw "invalid hdc handle";
    }
    std::cout << "This app have no visible windows" << std::endl;
}


int RAM::read_bytes(LPCVOID addr, int num, void* buf)
{
    SIZE_T sz = 0;
    int r = ReadProcessMemory(hProcess, addr, buf, num, &sz);
    if ( r == 0 || sz == 0 )
    {
        printf("RPM error, %08X\n", "errorStatus:t", GetLastError(), "\tbyteSIze:", sz, "\tr size:", r);
        return 0;
    }
    return 1;
}


template<typename T>
fastfunc T RAM::ReadMemoryArray(ADDRESS start_address, ADDRESS end_address)
{
    end_address -= end_address % sizeof(T);
    T* buf = new T[end_address - start_address / sizeof(T)];
    for ( ; start_address <= end_address; start_address++ )
        read_bytes((LPCVOID)start_address, sizeof(T), &buf);
    return buf;
}


fastfunc bool RAM::DataCompare(const BYTE* pData, const BYTE* pMask, const char* pszMask)
{
    for ( ; *pszMask; ++pszMask, ++pData, ++pMask )
    {
        if ( *pszMask == 'x' && *pData != *pMask )
        {
            return false;
        }
    }
    return ( *pszMask == NULL );
}


fastfunc bool RAM::DataCompare(const BYTE* readed_data, const BYTE* signature, const char* mask, size_t size)
{   
    size_t i = 0;
    for ( ; i < size; ++i, ++readed_data )
    {
        if ( mask[i] == 'x' && *readed_data != signature[i] )
        {
            return false;
        }
    }
    return ( i != NULL );
}


DWORD RAM::FindPattern(DWORD start, DWORD size, CONST BYTE* sig, LPCSTR mask, size_t masksize)
{
    if ( !size ) throw "zero bytes to compare"s;

    BYTE* data = new BYTE[size+1];
    std::fill_n(data, size + 1, 0);
    SIZE_T bytesread = NULL;

    // Проверка на защиту памяти от чтения
    if ( !this->IsMemoryReadable((void*)start, size) ) std::cerr << "cannot read memory" << ": " << "Memory block is not readable by protect" << std::endl;

    ReadProcessMemory(hProcess, (LPCVOID)start, data, size, &bytesread);
    if ( bytesread <= 0 )
        std::cerr << "cannot read memory" << ": " << "error:" << " " << GetLastError() << std::endl;
        throw "FindPattern -> cannot read memory"s;

    for ( DWORD i = 0; i < size; i++ )
    {
        if ( DataCompare(( CONST BYTE* )( data + i ), ( CONST BYTE* )sig, mask, masksize) )
        {
            delete( data );
            return start + i;
        }
    }

    delete( data );
    return NULL;
}


DWORD RAM::FindPattern(DWORD start, DWORD size, CONST BYTE* sig, LPCSTR mask)
{
    if ( !size ) throw "zero bytes to compare"s;

    BYTE* data = new BYTE[size];
    SIZE_T bytesread = NULL;
    ReadProcessMemory(hProcess, (LPCVOID)start, data, size, &bytesread);
    if ( bytesread <= 0 )
        throw "FindPattern -> cannot read memory"s;
    for ( DWORD i = 0; i < size; i++ )
    {
        if ( DataCompare(( CONST BYTE* )( data + i ), ( CONST BYTE* )sig, mask))
        {
            delete( data );
            return start + i;
        }
    }
    delete( data );
    return NULL;
}


DWORD RAM::FindPatternArray(DWORD start, DWORD size, LPCSTR mask, int count, ...)
{
    byte* sig = new byte[count + 1];
    va_list ap;
    va_start(ap, count);
    for ( int i = 0; i < count; i++ )
    {
        char read = va_arg(ap, char);
        sig[i] = read;

    }
    va_end(ap);
    sig[count] = '\0';
    return FindPattern(start, size, sig, mask, count);
}


//TODO:
//FIXME:
DWORD RAM::FindPatternArray(DWORD start, DWORD size, std::string mask, ...)
{
    size_t count = mask.size();
    byte* sig = new byte[count + 1];
    va_list ap;
    va_start(ap, count);
    for ( int i = 0; i < count; i++ )
    {
        char read = va_arg(ap, char);
        sig[i] = read;

    }
    va_end(ap);
    sig[count] = '\0';
    return FindPattern(start, size, sig, mask.c_str(), mask.size());
}


DWORD RAM::FindPatternArray(DWORD start, DWORD size, Pattern pattern)
{
    byte* sig = new byte[pattern.bytes.size()+1];
    for ( size_t i = 0; i < pattern.bytes.size(); ++i )
        sig[i] = pattern.bytes[i];
    sig[pattern.bytes.size()] = '\0';

    LPCSTR mask = pattern.mask_str.c_str();
    return FindPattern(start, size, sig, mask, pattern.bytes.size());
}


std::vector<DWORD> RAM::FindAllPatterns(DWORD startAddress, DWORD end_address, LPCSTR mask, int patterns_counter, std::vector<BYTE> sign)
{
    auto count = sign.size();
    byte* sig = new byte[count + 1];
    for ( int i = 0; i < count; i++ )
    {
        char read = sign[i];
        sig[i] = read;

    }
    sig[count] = '\0';

    std::vector<DWORD> patern_addresses;
    DWORD checksize = 0xFF;
    for ( int i = 0; i < patterns_counter; ++i )
    {
        for ( DWORD64 currentaddress = startAddress; currentaddress < end_address;)
        {
            auto finded = FindPattern(currentaddress, checksize, sig, mask);

            if ( startAddress < end_address && finded < end_address && finded )
            {
                patern_addresses.push_back(finded);
                currentaddress = patern_addresses[patern_addresses.size() - 1] + 1;
                continue;
            }
            if ( currentaddress > end_address )
                throw( 1 );
            currentaddress += checksize;
        }
        delete sig;
        if ( patern_addresses.size() )
            return patern_addresses;
        else
            throw( 0xAB0BA );
    }
    return patern_addresses;
}


bool RAM::IsMemoryReadable(void* ptr, size_t byteCount)
{
    MEMORY_BASIC_INFORMATION temp_mbi;
    if ( VirtualQuery(ptr, &temp_mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0 )
        return false;

    if ( temp_mbi.State != MEM_COMMIT )
        return false;

    if ( temp_mbi.Protect == PAGE_NOACCESS || temp_mbi.Protect == PAGE_EXECUTE )
        return false;

    size_t blockOffset = (size_t)( (char*)ptr - (char*)temp_mbi.AllocationBase );
    size_t blockBytesPostPtr = temp_mbi.RegionSize - blockOffset;

    if ( blockBytesPostPtr < byteCount )
        return this->IsMemoryReadable(
            (char*)ptr + blockBytesPostPtr,
            byteCount - blockBytesPostPtr);

    return true;
}


ADDRESS RAM::VerificatePattern(ADDRESS pattern2verificate, std::pair<ADDRESS, ADDRESS> range, LPCSTR mask, std::vector<BYTE> pattern_sign)
// Эта штука должна находить байтовый паттерн, который может находиться только рядом с нужным адресом
// pattern2verificate - адрес, от которого искать
// range - область допустимых адресов вниз и вверх относительно адреса паттерна, который нужно проверить(как далеко искать)
// pattern_sign - массив байт, при нахождении которого в определенной области, можно быть уверенным, что паттерн тот, который нужен
// паттерн для верификации должен отличаться от верифицируемого паттерна
{
    auto count = pattern_sign.size();
    byte* sig = new byte[count + 1];
    for ( int i = 0; i < count; i++ )
    {
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
    for ( ;; Sleep(1000) )
    {
        if ( process_name != L"" && window_name != L"" )
        {
            if ( this->GetProcessHandle(process_name.c_str()) && this->getWindowHandle(window_name.c_str()) )
                return;
        }
        else
        {
            if ( this->process_name == L"" || this->window_name == L"" )
                throw( 0xAB0BA );
            process_name = this->process_name;
            window_name = this->window_name;
        }

    }
}


void RAM::WaitProcess(std::wstring process_name)
{
    for ( ;; Sleep(1000) )
    {
        if ( process_name != L"" )
        {
            if ( this->GetProcessHandle(process_name.c_str()) )
                return;
        }
        else
        {
            if ( this->process_name == L"" )
                throw( 0xAB0BA );
            process_name = this->process_name;
        }

    }
}


void RAM::WaitProcess()
{
    if ( this->process_name == L"" || this->window_name == L"" )
        throw( 0xAB0BA );
    for ( ;; Sleep(1000) )
        if ( this->GetProcessHandle(this->process_name.c_str()) && this->getWindowHandle(this->window_name.c_str()) )
            return;
}


void RAM::GetWindow()
{
    if ( this->dwProcId )
    {
        this->hWindow = this->FindTopWindow();
        this->GetHDC();
    }
    else
    {
        this->hWindow = this->getWindowHandle(this->window_name.c_str());
    }
}


HWND RAM::FindTopWindow()
{
    if ( !this->dwProcId )
        throw "FindTopWindow -> Cannot get process id"s;
    DWORD pid = this->dwProcId;
    std::pair<HWND, DWORD> params = { 0, pid };

    BOOL bResult = EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL
    {
        auto pParams = ( std::pair<HWND, DWORD>* )( lParam );

        DWORD processId;
        if ( GetWindowThreadProcessId(hwnd, &processId) && processId == pParams->second )
        {
            SetLastError(-1);
            pParams->first = hwnd;
            return false;
        }

        return true;
    }, (LPARAM)&params);

    if ( !bResult && GetLastError() == -1 && params.first )
    {
        return params.first;
    }

    return 0;
}



DllModule::DllModule()
{
    offsets.clear();
    handle_base = 0x0;
    module_size = 0x0;
}


DllModule::DllModule(const wchar_t* name)
{
    offsets.clear();
    this->name = name;
    module_base_size = ram_ptr->GetModule(this->name);
    handle_base = module_base_size.first;
    module_size = module_base_size.second;
}


DllModule::DllModule(const wchar_t* name, RAM ram)
{
    offsets.clear();
    this->name = name;
    module_base_size = ram.GetModule(this->name);
    handle_base = module_base_size.first;
    module_size = module_base_size.second;
}


const wchar_t* DllModule::GetName()
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


void DllModule::GetModule(std::wstring module_name)
{
    offsets.clear();
    this->name = module_name.c_str();
    module_base_size = ram_ptr->GetModule(this->name);
    handle_base = module_base_size.first;
    module_size = module_base_size.second;
}


class Application
{
    SYSTEM_INFO system_info;
public:
    std::wstring Name;
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
        this->Name = std::wstring(wtmp.begin() + std::distance(wtmp.begin(), wtmp.begin() + wtmp.find_last_of(L'\\') + 1), wtmp.end());
        Ram.process_name = std::wstring(this->Name);
        Ram.GetProcessHandle(this->Name.c_str());
    }

    Application(LPCWSTR process_name) // Повинно закiнчуватися на .exe
    {
        this->Name = std::wstring(process_name);
        Ram.process_name = std::wstring(process_name);
        memset(&this->system_info, 0, sizeof(system_info));
        GetSystemInfo(&system_info);

        Ram.GetProcessHandle(process_name);
        Ram.GetWindow();
    }

    std::pair<LPVOID, LPVOID> GetBaseEnd()
    {
        return std::make_pair(system_info.lpMinimumApplicationAddress, system_info.lpMaximumApplicationAddress);
    }
};


Application this_application = Application();
