// payload.cpp : 定义静态库的函数。
//
#include "shellcode.h"
#include "xorstr.hpp"
#include "lazy_importer.hpp"
#include <string>
// TODO: 这是一个库函数示例

#ifndef _WIN64

__declspec(naked) uint8_t* getEip()
{
    __asm
    {
        call NEXT
        NEXT :
        pop eax
        ret
    }
}

SC_EXPORT DWORD fix(LPVOID lpParameter)
{
    uint8_t* eax = getEip();

    do
    {
        if (eax[0] != 0xDE ||
            eax[1] != 0xC0 ||
            eax[2] != 0xAD ||
            eax[3] != 0xDE
            )
        {
            eax--;
            continue;
        }
        else
            break;

    } while (true);

    uint8_t* base = eax;
    eax = getEip();

    do {
        if (eax[0] != 0xDE ||
            eax[1] != 0xC0 ||
            eax[2] != 0xAD ||
            eax[3] != 0xDE
            )
        {
            eax++;
            continue;
        }
        else
            break;

    } while (true);

    uint8_t* dir_rel = eax;
    uint32_t count = *(uint32_t*)(dir_rel + 0x4);

    dir_rel += 0x8;

    if (count > 0)
    {
        for (uint32_t i = 0; i < count; i++)
        {
            uint32_t* place = (uint32_t*)((*(uint32_t*)dir_rel) + base + 0x4);
            *place = (uint32_t)(*place + base + 0x4);
            dir_rel += 0x4;
        }
    }

    return 0;
}


#endif // 

extern void ShellcodeFunctionCallExternExample(void);
const char* globalStr = "helloworld";
const char* globalStr1 = "你好中国：》";
int globalVar = 0x414141;

void printStatic()
{
    static int sta = 0;
    LI_FN(printf)("static value: %d\n", sta++);
}


/* shallcode 入口示例 */
SC_EXPORT DWORD ShellcodeFunctionEntryPointExample(LPVOID lpParameter)
{

    // 调试输出
    DbgPrint("Thread lpParameter %d", lpParameter);

    // 使用 sprintf 、 字符串 、 以及编译器常量 
    /*
    32位 CHAR buf[512] = { 0 }会调用c库函数_memset, 64位使用rep指令
    所以32位不应这样初始化，需显示调用LI_FN(memset)或者使用宏SecureZeroMemory
    */
    CHAR buf[512];
    SecureZeroMemory(buf, sizeof(buf));
    LI_FN(sprintf)(buf, "Hello The thread parameter is 0x%p and The function name is %s", lpParameter, __FUNCTION__);

    //使用系统 API
    LI_FN(MessageBoxA)(HWND(0), buf,"Display from shellcode", MB_OK | MB_TOPMOST);

    LI_FN(printf)("globalVar: %d\n",globalVar);
    LI_FN(printf)("globalStr: %s\n",globalStr);
    LI_FN(printf)("globalStr: %s\n", globalStr1);

    // 跨.cpp调用函数 可以通过 extern，也可以通过在共同头文件中给出声明
    ShellcodeFunctionCallExternExample();

    int count = 0;

    do {
        printStatic();
        count++;
    } while (count < 3);

    auto a = [](const char* str)
    {
        LI_FN(printf)("lambda str: %s\n", str);
    };

    a("lambda test");

    return 0;
}
