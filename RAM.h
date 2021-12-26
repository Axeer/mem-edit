//last changes: 08.31.2021
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

typedef DWORD ADDRESS;
typedef std::wstring wstr;

int wstrcmp( const wchar_t *str1, const wchar_t *str2 );
byte new_wstrcmp( const wchar_t *str1, const wchar_t *str2 );

int wstrcmp( const wchar_t *str1, const wchar_t *str2 )
{
	short sh_strIndex = 0;
	short symbols_ident = 0;
	short symbols_remaining = 0;
	if ( str1[sh_strIndex] == '\0' || str2[sh_strIndex] == '\0' )
		return 0xfff;
	while ( str1[sh_strIndex] != '\0' && str2[sh_strIndex] != '\0' )
	{
		if ( str1[sh_strIndex] == str2[sh_strIndex] )
			symbols_ident++;
		//check if first word end
		if ( str1[sh_strIndex] == '\0' && str2[sh_strIndex] != '\0' )
		{
			for ( ; str2[sh_strIndex] != '\0'; symbols_remaining++ )
			{
				sh_strIndex++;
			}
			return symbols_remaining;
		}
		//check if second word end
		if ( str1[sh_strIndex] != '\0' && str2[sh_strIndex] == '\0' )
		{
			for ( ; str1[sh_strIndex] != '\0'; symbols_remaining++ )
			{
				sh_strIndex++;
			}
			return symbols_remaining;
		}
		sh_strIndex++;
	}
	//for (int i_str2Length =0;str2[i_str2Length]!='\0';i_str2Length++)
	//for (int i_str1Length = 0; str1[i_str1Length] != '\0'; i_str1Length++)
		//if (j == i_str2Length) {
	if ( str1[sh_strIndex] == '\0' && str2[sh_strIndex] == '\0' && symbols_ident != 0 && symbols_remaining == 0 )
		return 0;
	//}
	else return 0x8000;
};

byte new_wstrcmp( const wchar_t *str1, const wchar_t *str2 )
{
	byte not_lenght_equal = 0xFF;
	byte not_symbol_equal = 0xFE;
	byte equal = 0x0;
	if ( lstrlenW( str1 ) != lstrlenW( str2 ) )
	{
		return not_lenght_equal;
	}
	for ( byte i = lstrlenW( str1 ); i > 0; --i )
	{
		if ( str1[i] != str2[i] )
		{
			return not_symbol_equal;
		}
	}
	return equal;
}


class RAM
{
public:
	DWORD pid;
	DWORD module_dll_base;
	DWORD dwProcId;
	const char* module_dll = "\0";
	HANDLE hProcess;
	HWND hWindow;
	HDC hDC;

	HANDLE handles[ 32 ];
	HMODULE hMods;

	MEMORY_BASIC_INFORMATION    mbi;

	std::wstring process_name = L"";
	std::wstring window_name = L"";

	template <typename T>
	T __fastcall read( HANDLE  address );

	template <typename T>
	void __fastcall write( HANDLE address, T value );

	template <typename T, size_t N>
	size_t countof( T( &array )[ N ] );

	template <typename T>
	void parse_memory_area( DWORD addr, short size );

	template <typename T>
	T sequential_read( DWORD address_base, std::vector<DWORD> offsets );

	template <typename T>
	void print_array( );

	template <typename T>
	T multiple_jump( T addr, DWORD offsets[], short& jumpCompleted );

	template<typename T>
	std::vector<DWORD> FindValue( T val );

	int CompareModules( wchar_t* str1, wchar_t* str2 );//Deprecated

	DWORD getModuleHandle( HMODULE hMods[] );

	std::pair<HANDLE, DWORD>GetModule( const wchar_t* modulename );

	DWORD getMultiModuleHandle( );

	HANDLE getProcessHandle( const wchar_t* window_name );//Deprecated

	DWORD GetProcessHandle( const wchar_t* process_name_exe );

	HWND getWindowHandle( const wchar_t* wch_window_name );

	HDC GetHDC( );

	int read_bytes( LPCVOID addr, int num, void* buf );

	DWORD getMemoryArea( DWORD from, DWORD to, void* type );

	bool DataCompare( const BYTE* pData, const BYTE* pMask, const char* pszMask );

	DWORD FindPattern( DWORD start, DWORD size, LPCSTR sig, LPCSTR mask );//find pattern in address space of process

	DWORD FindPatternArray( DWORD start, DWORD size, LPCSTR mask, int count, ... );//find pattern array in address space of process

	std::vector<DWORD> FindAllPatterns( DWORD startAddress, DWORD size, LPCSTR mask, int patterns_counter, std::vector<BYTE> sign );

	bool IsMemoryReadable( void* ptr, size_t byteCount );

	ADDRESS VerificatePattern( ADDRESS pattern2verificate, std::pair<ADDRESS, ADDRESS> range, LPCSTR mask, std::vector<BYTE> pattern_sign );

	void WaitProcess(std::wstring process_name, std::wstring window_name);
	void WaitProcess(std::wstring process_name);
	void WaitProcess();
};


class DllModule
{
	HANDLE						handle_base;
	DWORD						module_size;
	std::vector < DWORD >		offsets;
	const wchar_t*				name;
	std::pair < HANDLE, DWORD >	module_base_size;
public:

	DllModule( );
	DllModule( const wchar_t* name );
	const wchar_t* GetName( );
	HANDLE						GetBase( );
	void						SetBase( HANDLE val );
	void						AddOffset( DWORD val );
	void						AddOffsets( std::vector<DWORD> offsets );
	DWORD						GetOffsset( USHORT index );
	std::vector<DWORD>			GetOffssets( );
	std::pair<HANDLE, DWORD>	GetModuleBaseEnd( );
	DWORD						GetSize( );

};

template <typename DataType>
class Item
//представляет набор данных в адресном пространстве памяти как единый объект, созданный для конкретной цели
{
public:
	std::string id;
	DWORD baseAddress;
	std::vector<DWORD> addresses;
	std::vector<DataType> values;
};



template <typename T>
T __fastcall RAM::read( HANDLE  address )
{
	T _read;
	ReadProcessMemory( hProcess, ( LPCVOID ) address, &_read, sizeof( T ), NULL );
	return _read;
}


template <typename T>
void __fastcall RAM::write( HANDLE address, T value )
{
	WriteProcessMemory( hProcess, ( LPVOID ) address, &value, sizeof( T ), NULL );
}


template <typename T, size_t N>
size_t RAM::countof( T( &array )[ N ] )
{
	return N;
}


template <typename T>
void RAM::parse_memory_area( DWORD addr, short size )
{
	T _readbuf;
	while ( !size == 0 )
	{
		ReadProcessMemory( hProcess, addr, &_readbuf, sizeof( addr ), NULL );
	}
}


template <typename T>
T RAM::sequential_read( DWORD address_base, std::vector<DWORD> offsets/*DWORD address, short bytesToRead*/ )
{
	/*DWORD _read;
	DWORD _readedArray[64];
	short bytesCount;
	if (bytesToRead > 64) { int i; int *b = &i; std::cout<<b; }
	for (int i = 0; i <= bytesToRead; i++, bytesCount++) {
		ReadProcessMemory(hProcess, (address + i * sizeof(T)), &_read, sizeof(T));
	}
	return { _readedArray, bytesCount };*/
	DWORD _base = this->read<DWORD>( address_base );
	T _output;
	USHORT _cntr = offsets.size( );
	for ( auto i : offsets )
	{
		_cntr--;
		if ( !_cntr )
		{
			_output = this->read<T>( _base + i );
			return _output;
		}
		_base = this->read<DWORD>( _base + i );
	}

}


template <typename T>
void RAM::print_array( )
{
	for ( short i = 0; i < countof( T ); i++ )
	{
		std::cout << '[' << i << ']' << T[ i ] << '\n';
	}
}


template <typename T>
T RAM::multiple_jump( T addr, DWORD offsets[], short& jumpCompleted )
{
	DWORD buf[ 2 ];
	short amount_of_jumps = 0;
	LPDWORD* ptrToOffsets = &offsets;
	for ( int i = 0; ptrToOffsets != nullptr; i++ )
	{
		amount_of_jumps++;
	}
	buf[ 0 ] = addr;
	short jumpCompl = 0;
	int data_size = sizeof( T );
	for ( int i = 0; amount_of_jumps != 0; i++ )
	{
		buf[ 0 ] = read<DWORD>( buf[ 0 ] += offsets[ i ] );
		if ( buf[ 0 ] != 0 )
		{
			jumpCompleted++;
		}
		else
		{
			std::cout << "multiple jump error "; return 0;
		}
	}
	return buf[ 0 ];
}


template<typename T>
std::vector<DWORD> RAM::FindValue( T val )
{
	SYSTEM_INFO system_info;
	GetSystemInfo( &system_info );
	std::vector<DWORD> addresses;
	auto start_ptr = system_info.lpMinimumApplicationAddress;
	auto end_ptr = system_info.lpMaximumApplicationAddress;
	uint32_t* current_ptr = reinterpret_cast< UINT32* >( start_ptr );

	while ( current_ptr < end_ptr )
	{
		MEMORY_BASIC_INFORMATION mbi;
		auto bytes = VirtualQueryEx( this->hProcess, current_ptr, &mbi, sizeof( mbi ) );
		if ( mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE )
		{
			std::vector<uint8_t> read_buffer( mbi.RegionSize );
			SIZE_T read_byte;
			if ( ReadProcessMemory( this->hProcess, current_ptr, read_buffer.data( ), mbi.RegionSize, &read_byte ) == TRUE )
			{
				T* current_page_ptr = reinterpret_cast< T* >( read_buffer.data( ) );
				while ( ( UINT8* ) current_page_ptr < read_buffer.data( ) + read_buffer.size( ) )
				{
					if ( *current_page_ptr == val )
					{
						addresses.push_back( reinterpret_cast< DWORD >( ( ( reinterpret_cast< UINT8* >( current_page_ptr ) ) - read_buffer.data( ) ) + reinterpret_cast< UINT8* >( mbi.BaseAddress ) ) );
					}
					current_page_ptr = reinterpret_cast< T* >( reinterpret_cast< char* >( current_page_ptr ) + 1 );
				}
			}
		}
		current_ptr += mbi.RegionSize;
	}
	return addresses;
}


//Deprecated
int RAM::CompareModules( wchar_t* str1, wchar_t* str2 )
{
	unsigned long str1_symbols = 0;
	unsigned long str2_symbols = 0;
	int counter = 0;
	for ( int i = 0; str1[ i ] != '\0'; i++ )
	{
		str1_symbols++;
	}
	for ( int j = 0; str2[ j ] != '\0'; j++ )
	{
		str2_symbols++;
	}
	for ( ; str2_symbols != 0; str2_symbols-- )
	{
		if ( str1[ str1_symbols ] == str2[ str2_symbols ] )
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


DWORD RAM::getModuleHandle( HMODULE hMods[] )
{
	unsigned i;
	for ( i = 0; i < ( pid / sizeof( HMODULE ) ); i++ )
	{
		wchar_t szModName[ MAX_PATH ];
		if ( K32GetModuleFileNameExW( hProcess, hMods[ i ], szModName,
									  sizeof( szModName ) / sizeof( TCHAR ) ) )
		{
			if ( strcmp( ( char* ) szModName, ( char* ) module_dll ) == NULL )
			{
				if ( CompareModules( ( wchar_t* ) szModName, ( wchar_t* ) module_dll ) == 0 )
				{
					printf( "client.dll base: %08X\n", hMods[ i ] );
					module_dll_base = ( DWORD ) hMods[ i ];
					return module_dll_base;
				}
				continue;
			}
		}
	}
}


std::pair<HANDLE, DWORD>RAM::GetModule( const wchar_t* modulename )
{

	HANDLE h_module = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwProcId );
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof( mEntry );
	if ( ( DWORD ) hProcess == ( DWORD ) 0x0 )
	{
		std::cerr << "HANDLE GetModule() -> no have handle of process" << std::endl;
		throw "no handle of process\n";
		exit( 0xAB0BA );
	}
	do
	{
		if ( !new_wstrcmp( ( wchar_t* ) mEntry.szModule, ( wchar_t* ) modulename ) )
		{
			//Smodule module = { (DWORD)mEntry.hModule, mEntry.modBaseSize };
			return std::make_pair( mEntry.hModule, mEntry.modBaseSize );

		}
	}
	while ( Module32Next( h_module, &mEntry ) );
	std::wcout << L"Find " << modulename << L" module failed" << std::endl;
	return std::make_pair( ( HANDLE ) 0, ( DWORD ) 0 );
}


DWORD RAM::getMultiModuleHandle( )
{
	HMODULE hModsArray[ 32 ];
	K32EnumProcessModules( hProcess, hModsArray, sizeof( hModsArray ), &pid );

	for ( int i = 0; i <= sizeof( hModsArray ); i++ )
	{
		std::cout << "loaded module from process\n";
		std::cout << hModsArray[ i ] << '\n';
		if ( ( int ) hModsArray[ i ] == 0xcccccccc )
			break;

	}
	Sleep( 4000 );
	return 0;
}


//Deprecated
HANDLE RAM::getProcessHandle( const wchar_t* window_name )
{
	HWND hWnd;
	HDC hDC;
	hWnd = FindWindow( 0, window_name );
	if ( hWnd == 0 )
	{
		printf( "FindWindow failed, %08X\n", GetLastError( ) );
		return NULL;
	}
	else
	{
		std::cout << "handle of window:\t" << hWnd << '\n';
	}
	GetWindowThreadProcessId( hWnd, &pid );
	std::cout << "process id is:\t" << pid << '\n';
	if ( pid == NULL )
	{
		std::cout << "find process id failed\n"; GetLastError( );
	}
	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid );
	if ( hProcess == 0 )
	{
		printf( "OpenProcess failed, %08X\n", GetLastError( ) );
		return NULL;
	}
	else
	{
		std::cout << "handle of process:\t" << hWnd << '\n';
	}
	hDC = GetDC( hWnd );
	HMODULE hModsArray[ 1024 ];
	HMODULE hMods;
	int i;
	if ( K32EnumProcessModules( hProcess, hModsArray, sizeof( hModsArray ), &pid ) == 0 )
	{
		printf( "enumprocessmodules failed, %08X\n", GetLastError( ) );
	}
	else
	{
		getModuleHandle( ( HMODULE* ) hModsArray );
	}

	return hProcess;
}


DWORD RAM::GetProcessHandle( const wchar_t* process_name_exe )
{
	DWORD dw_rights = PROCESS_VM_READ;
	HANDLE handle = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof( entry );
	do
	{
		if ( !new_wstrcmp( ( const wchar_t* ) entry.szExeFile, ( const wchar_t* ) process_name_exe ) )
		{
			dwProcId = entry.th32ProcessID;
			CloseHandle( handle );
			hProcess = OpenProcess( dw_rights, false, dwProcId );
			return ( DWORD ) hProcess;
		}
	}
	while ( Process32Next( handle, &entry ) );
	return ( DWORD ) false;
}


HWND RAM::getWindowHandle( const wchar_t* wch_window_name )
{
	if ( lstrlenW( wch_window_name ) == NULL )
	{
		std::cerr << "HWND getWindowHandle() -> no have window name" << std::endl;
	}
	hWindow = FindWindow( 0, wch_window_name );
	return hWindow;
}


HDC RAM::GetHDC( )
{
	if ( hWindow != NULL )
	{
		this->hDC = GetWindowDC( hWindow );
		if ( this->hDC != NULL )
		{
			return this->hDC;
		}
		std::cout << "invalid hdc handle" << std::endl;
		throw "invalid hdc handle";
	}
	std::cout << "no have window handle" << std::endl;
	throw "no have window handle";
}


int RAM::read_bytes( LPCVOID addr, int num, void* buf )
{
	SIZE_T sz = 0;
	int r = ReadProcessMemory( hProcess, addr, buf, num, &sz );
	if ( r == 0 || sz == 0 )
	{
		printf( "RPM error, %08X\n", "errorStatus:t", GetLastError( ), "\tbyteSIze:", sz, "\tr size:", r );
		return 0;
	}
	return 1;
}


DWORD RAM::getMemoryArea( DWORD from, DWORD to, void* type )
{
	unsigned buf[ 256 ];
	for ( ; from <= to; from++ )
	{
		read_bytes( ( LPCVOID ) from, sizeof( type ), &buf );
	}
	//print_array((char*)buf, NULL);
	return ( DWORD ) buf;
}


FORCEINLINE bool RAM::DataCompare( const BYTE* pData, const BYTE* pMask, const char* pszMask )
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

/*
//find pattern in address space of process
DWORD RAM::FindPattern( DWORD start, DWORD size, LPCSTR sig, LPCSTR mask )
{
	BYTE* data = new BYTE[ size ];  // TODO: вызывает bad allocation из-за попытки аллокации APP SIZE количества байтов(дохуя короче)
	DWORD bytesread = NULL;
	if ( !ReadProcessMemory( hProcess, ( LPCVOID ) start, data, size, ( SIZE_T* ) &bytesread ) )
	{
		return NULL;
	}
	for ( DWORD i = 0; i < size; i++ )
	{
		if ( DataCompare( ( CONST BYTE* )( data + i ), ( CONST BYTE* )sig, mask ) )
		{
			delete( data );
			return start + i;
		}
	}
	return NULL;
}
*/
/*
//find pattern in address space of process
DWORD RAM::FindPattern( DWORD start, DWORD size, LPCSTR sig, LPCSTR mask )
{
	std::pair<DWORD, DWORD> base = std::make_pair(start, 0);
	DWORD def_size = strlen( mask );
	DWORD bytesread = NULL;
	for(DWORD x = 0;size >= def_size; size -= def_size)
	{
		
		auto i = std::make_pair( ( BYTE* ) new BYTE[ def_size ], ( DWORD ) def_size );
		auto len = i.second;
		ReadProcessMemory( hProcess, ( LPCVOID ) start, i.first, len, ( SIZE_T* ) &bytesread );
		start += 1;	

		//for ( DWORD ii = 0; ii < len; ii++ )
		//{
		if ( DataCompare( ( CONST BYTE* )( i.first ), ( CONST BYTE* )sig, mask ) )
		{
			return base.first + base.second;
		}
		base.second += 1;
		//}
		delete( i.first );
	}
	return NULL;
}
*/

//find pattern in address space of process
DWORD RAM::FindPattern( DWORD start, DWORD size, LPCSTR sig, LPCSTR mask )
{
	BYTE* data = new BYTE[ size ];  // TODO: вызывает bad allocation из-за попытки аллокации APP SIZE количества байтов(дохуя короче)
	DWORD bytesread = NULL;
	ReadProcessMemory( hProcess, ( LPCVOID ) start, data, size, ( SIZE_T* ) &bytesread );
	for ( DWORD i = 0; i < size; i++ )
	{
		if ( DataCompare( ( CONST BYTE* )( data + i ), ( CONST BYTE* )sig, mask ) )
		{
			delete( data );
			return start + i;
		}
	}
	delete( data );
	return NULL;
}

//find pattern array in address space of process
DWORD RAM::FindPatternArray( DWORD start, DWORD size, LPCSTR mask, int count, ... )
{
	char* sig = new char[ count + 1 ];
	va_list ap;
	va_start( ap, count );
	for ( int i = 0; i < count; i++ )
	{
		char read = va_arg( ap, char );
		sig[ i ] = read;

	}
	va_end( ap );
	sig[ count ] = '\0';
	return FindPattern( start, size, sig, mask );
}


std::vector<DWORD> RAM::FindAllPatterns( DWORD startAddress, DWORD end_address, LPCSTR mask, int patterns_counter, std::vector<BYTE> sign)
// TODO: отьедает дохера памяти, исправить.
{
	auto count = sign.size( );
	char* sig = new char[ count + 1 ];
	for ( int i = 0; i < count; i++ )
	{
		char read = sign[ i ];
		sig[ i ] = read;

	}
	sig[ count ] = '\0';

	std::vector<DWORD> patern_addresses;
	DWORD checksize = 0xFF;
	for ( int i = 0;i < patterns_counter;++i )
	{
		for ( DWORD64 currentaddress = startAddress; currentaddress < end_address;)
		{
			auto finded = FindPattern( currentaddress, checksize, sig, mask );

			if ( startAddress < end_address && finded < end_address && finded )
			{
				patern_addresses.push_back( finded );
				currentaddress = patern_addresses[ patern_addresses.size( ) - 1 ] + 1;
				continue;
			}
			if ( currentaddress > end_address )
				throw( 1 );
			currentaddress += checksize;
		}
		delete sig;
		if ( patern_addresses.size( ) )
			return patern_addresses;
		else
			throw( 0xAB0BA );
	}
	return patern_addresses;
}


bool RAM::IsMemoryReadable( void* ptr, size_t byteCount )
{
	MEMORY_BASIC_INFORMATION temp_mbi;
	if ( VirtualQuery( ptr, &temp_mbi, sizeof( MEMORY_BASIC_INFORMATION ) ) == 0 )
		return false;

	if ( temp_mbi.State != MEM_COMMIT )
		return false;

	if ( temp_mbi.Protect == PAGE_NOACCESS || temp_mbi.Protect == PAGE_EXECUTE )
		return false;

	  // This checks that the start of memory block is in the same "region" as the
	  // end. If it isn't you "simplify" the problem into checking that the rest of 
	  // the memory is readable.
	size_t blockOffset = ( size_t ) ( ( char* ) ptr - ( char* ) temp_mbi.AllocationBase );
	size_t blockBytesPostPtr = temp_mbi.RegionSize - blockOffset;

	if ( blockBytesPostPtr < byteCount )
		return this->IsMemoryReadable(
			( char* ) ptr + blockBytesPostPtr,
			byteCount - blockBytesPostPtr );

	return true;
}

ADDRESS RAM::VerificatePattern( ADDRESS pattern2verificate, std::pair<ADDRESS, ADDRESS> range, LPCSTR mask, std::vector<BYTE> pattern_sign )
// Эта штука должна находить паттерн, который может находиться рядом только с нужным адресом
// pattern2verificate - адрес паттерна, который нужно проверить
// range - область допустимых адресов вниз и вверх относительно адреса паттерна, который нужно проверить(как далеко искать)
// pattern_sign - массив байт, при нахождении которого в определенной области, можно быть уверенным, что паттерн тот, который нужен
// паттерн для верификации должен отличаться от верифицируемого паттерна
{
	auto count = pattern_sign.size( );
	char* sig = new char[ count + 1 ];
	for ( int i = 0; i < count; i++ )
	{
		char read = pattern_sign[ i ];
		sig[ i ] = read;

	}
	sig[ count ] = '\0';
	auto currentaddress = pattern2verificate - range.first; // нижний предел поиска
	auto checksize = range.first + range.second;
	ADDRESS finded = FindPattern( currentaddress, checksize, sig, mask );
	return  finded - pattern2verificate;
	// возвращает дистанцию между найденым папттерном и верифицируемым
}


void RAM::WaitProcess(std::wstring process_name, std::wstring window_name) {
	for (;; Sleep(1000)) {
		if (process_name != L"" && window_name != L"") {
			if (this->GetProcessHandle(process_name.c_str()) && this->getWindowHandle(window_name.c_str()))
				return;
		}
		else {
			if (this->process_name == L"" || this->window_name == L"")
				throw(0xAB0BA);
			process_name = this->process_name;
			window_name = this->window_name;
		}

	}
}


void RAM::WaitProcess(std::wstring process_name) {
	for (;; Sleep(1000)) {
		if (process_name != L"") {
			if (this->GetProcessHandle(process_name.c_str()))
				return;
		}
		else {
			if (this->process_name == L"")
				throw(0xAB0BA);
			process_name = this->process_name;
		}

	}
}

void RAM::WaitProcess() {
	if (this->process_name == L"" || this->window_name == L"")
		throw(0xAB0BA);
	for (;; Sleep(1000))
		if (this->GetProcessHandle(this->process_name.c_str()) && this->getWindowHandle(this->window_name.c_str()))
			return;
}

RAM ram;

DllModule::DllModule( )
{
	offsets.clear( );
	handle_base = 0x0;
	module_size = 0x0;
}


DllModule::DllModule( const wchar_t* name )
{
	offsets.clear( );
	this->name = name;
	module_base_size = ram.GetModule( this->name );
	handle_base = module_base_size.first;
	module_size = module_base_size.second;
}


const wchar_t* DllModule::GetName( )
{
	return this->name;
}


HANDLE						DllModule::GetBase( )
{
	return handle_base;
}


void						DllModule::SetBase( HANDLE val )
{
	handle_base = val;
}


void						DllModule::AddOffset( DWORD val )
{
	offsets.push_back( ( DWORD ) val );
}


void						DllModule::AddOffsets( std::vector<DWORD> offsets )
{
	for ( auto i : offsets )
		this->offsets.push_back( i );
}


DWORD						DllModule::GetOffsset( USHORT index )
{
	return offsets[ index ];
}


std::vector<DWORD>			DllModule::GetOffssets( )
{
	return offsets;
}


std::pair<HANDLE, DWORD>	DllModule::GetModuleBaseEnd( )
{
	return this->module_base_size;
}


DWORD						DllModule::GetSize( )
{
	return this->module_base_size.second;
}

class Application
{
	SYSTEM_INFO system_info;
public:
	Application( )
	{
		memset( &this->system_info, 0, sizeof( system_info ) );
		GetSystemInfo( &system_info );
	}

	std::pair<LPVOID, LPVOID> GetBaseEnd( )
	{
		return std::make_pair( system_info.lpMinimumApplicationAddress, system_info.lpMaximumApplicationAddress );
	}
};
