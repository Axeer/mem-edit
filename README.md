 Кучка методов, которые я юзаю для удобства чтения и патчинга памяти в адресном пространстве рандомных приложений.
 
 Никакого читерства, только мир и цветочьки.

<b> Пример использования</b>

```cpp
int main(){
    Application app(L"firefox.exe");
    DllModule modules[] = { 
		L"some_lib1.dll",
		L"some_lib2.dll",
		L"some_lib3.dll",
		L"some_lib4.dll"};
    app.Ram.GetHDC();
    app.Ram.FindPatternArray( 
        (DWORD) modules[some_lib1].GetBase(),
        modules[some_lib1].GetSize(), 
	"xxxxxx????",
        strlen("xxxxxx????"),
        0x00, 0xC8, 0x5C, 0x70, 0x03, 0x0, 0x0, 0x0, 0x0 
    );
}
```
