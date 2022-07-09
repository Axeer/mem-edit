#include "pch.h"
#include <RAM.h>

TEST(TestCaseName, TestName) {
  EXPECT_EQ(1, 1);
  EXPECT_TRUE(true);

  EXPECT_EQ(wstrcmp(L"string_equal", L"string_equal"), 0);
  EXPECT_EQ(wstrcmp(L"string_equal", L"string_not_equal"), -1);
  EXPECT_EQ(wstrcmp(L"string_not_equal", L"string_equal"), 1);

    {
        auto pat1 = Pattern();
        EXPECT_EQ(pat1.bytes.size(), 0);
        EXPECT_EQ(pat1.mask.size(), 0);
    }

    {
        auto pat2 = Pattern({ 1,1,1,1,1 });
        EXPECT_EQ(pat2.bytes.size(), 5);
        EXPECT_EQ(pat2.mask.size(), 5);
    }

    {
        std::vector<byte> bytes = { 0x1,0x1,0x1,0x1,0x1 };
        std::vector<bool> required_pattern{ 1,1,0,1,1 };
        auto pattern = Pattern(bytes, required_pattern);
        std::vector<byte> pattern_result(pattern.bytes.begin(), pattern.bytes.end());

        EXPECT_EQ(pattern_result.size(), bytes.size());
        EXPECT_EQ(pattern.bytes, std::vector<byte>(pattern.mask.begin(), pattern.mask.end()));
    }

    {
        auto app = Application();
        EXPECT_TRUE(std::wstring(app.Name).length());
        //std::wcout << std::endl << app.Name << std::endl;
    }
    {
        Application app(L"hl.exe");
        auto base = DllModule();
        base.WithInstance(app);
        base.GetModule(L"hl.exe"s);
        app.Dlls.push_back(base);
        auto mask = "x?*11x*3?*3"s;
        auto pattern = Pattern({ 0x1c, 0x0, 0xff, 0x0}, mask);
        auto data = 0L;
        data = app.Ram.read<size_t>((HANDLE)app.Dlls[0].GetBase());
        auto result = app.Ram.FindPatternArray(
            (ADDRESS)app.Dlls[0].GetBase(),
            (ADDRESS)app.Dlls[0].GetSize(),
            pattern
        );
        std::cout << result << std::endl;
    }
}