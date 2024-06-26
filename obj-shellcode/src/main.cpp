
#include "lib.h"
#include <string>
#include <iostream>
#include <iomanip> 
#include "misc.hpp"
#include "rang_impl.hpp"

using namespace weaponslib2;

constexpr char out_bin_name[] = { "shellcode-payload.bin" };
constexpr char out_hpp_name[] = { "payload" };

struct section_mapped_info {
    uint32_t maped_va;
    uint32_t maped_size; // maped_size 好像用不到 先留着吧
};

void recursive_lookup_relocations(std::vector<lib>& libs,
    std::tuple<PIMAGE_SYMBOL, obj*> sym,
    std::unordered_map<PIMAGE_SECTION_HEADER, section_mapped_info>& section_mapped,
    std::unordered_map<std::string, int>& sym_mapped,
    std::vector<uint8_t>& shellcodebytes,
    std::vector<uint32_t>& dir_offset);

void print_shellcode_hpp_file(std::string                                                    resource_name,
    std::unordered_map<std::string, int>& sym_mapped,
    std::vector<uint8_t>& shellcodebytes,
    std::unordered_map<std::string, std::tuple<PIMAGE_SYMBOL, weaponslib2::obj*>>& export_syms);

int main()
{
	// 读取lib
	//using namespace weaponslib2;
#ifdef _WIN64
    lib liber("payload_Debug_x64.lib");
#else
    lib liber("payload_Debug_Win32.lib");
#endif // _WIN64

    if (!liber.isLib())
    {
        ERO("lib format error");
        return -1;
    }
	else
		INF("lib format checked");

    std::vector<lib> libs;
    libs.push_back(liber);

    std::unordered_map<std::string, std::tuple<PIMAGE_SYMBOL, obj*>> export_syms;
    
    for (auto& lib : libs)
    {
        for (auto& obj : lib.objs())
        {
            for (auto& exp : obj.exports()) 
            {
                obj.walkSymbols([&](IMAGE_SYMBOL& Sym) {
                    // 找到对应导出名称的符号 PIMAGE_SYMBOL
                    if (exp == obj.getSymbolNameByImageSymble(Sym)) 
                    {
                        if (export_syms.find(exp) == export_syms.end()) {
                            export_syms.insert({ exp, {&Sym, &obj} });
                        }
                        else {
                            throw std::exception("Duplicate export symbol:\"%s\"");
                        }
                    }
                    });
            }
        }
    }

    std::vector<uint8_t>                                 shellcodebytes; //储存映射数据的内存
    std::unordered_map<PIMAGE_SECTION_HEADER, section_mapped_info> section_mapped; //所有被映射的节
    std::unordered_map<std::string, int>                           sym_mapped;     //所有被映射的符号
    std::vector<uint32_t>dir_offset;
   
    dir_offset.push_back(0xDEADC0DE);

    for (auto& exp : export_syms) 
        recursive_lookup_relocations(libs, exp.second, section_mapped, sym_mapped, shellcodebytes, dir_offset);

     for (auto& i : sym_mapped)
         INF("[ 0x%06x ] for %s", i.second, i.first.c_str());
    std::vector<uint8_t> combined;
    
    //写出 bin
#ifndef _WIN64
    std::vector<uint32_t> magic;
    magic.push_back(0xDEADC0DE);
    dir_offset.insert(dir_offset.begin() + 1, dir_offset.size() - 1);
    auto a_magic = tcb::span<uint8_t>((uint8_t*)magic.data(), magic.size() * sizeof(uint32_t));
    combined.insert(combined.end(), a_magic.begin(), a_magic.end());
    combined.insert(combined.end(), shellcodebytes.begin(), shellcodebytes.end());
    auto a_dir_offset = tcb::span<uint8_t>((uint8_t*)dir_offset.data(), dir_offset.size() * sizeof(uint32_t));
    combined.insert(combined.end(), a_dir_offset.begin(), a_dir_offset.end());

#else
    combined = std::move(shellcodebytes);
#endif // _WIN64
   
    IMP("----------");
    for (auto& exp : export_syms)
        IMP("Export at [ 0x%06x ] for %s", sym_mapped[exp.first], exp.first.c_str());
    IMP("----------");

    buffer_to_file_bin(combined.data(), combined.size(), out_bin_name);
    //写出 hpp
    print_shellcode_hpp_file(out_hpp_name, sym_mapped, combined, export_syms);

    SUC("shellcode generator success!");

	return 0;
}


void recursive_lookup_relocations(std::vector<lib>& libs,
    std::tuple<PIMAGE_SYMBOL, obj*> sym,
    std::unordered_map<PIMAGE_SECTION_HEADER, section_mapped_info>& section_mapped,
    std::unordered_map<std::string, int>& sym_mapped,
    std::vector<uint8_t>& shellcodebytes,
    std::vector<uint32_t>& dir_offset
    ) {

    // 获取符号名称
    const char* pSymName = std::get<obj*>(sym)->getSymbolNameByImageSymble(*std::get<PIMAGE_SYMBOL>(sym));

    if (sym_mapped.find(pSymName) != sym_mapped.end()) return;

    // 符号表示节或者存在于节中
    if (std::get<PIMAGE_SYMBOL>(sym)->SectionNumber > IMAGE_SYM_UNDEFINED)
    {
        auto ss = std::get<obj*>(sym)->sections();
        IMAGE_SECTION_HEADER& section = ss[static_cast<size_t>(std::get<PIMAGE_SYMBOL>(sym)->SectionNumber) - 1];
 
        // 此符号表示节名
        if (std::get<PIMAGE_SYMBOL>(sym)->Value == 0)
        {
            // 复制节到shellcode
            if (section_mapped.find(&section) == section_mapped.end())
            {
                size_t oldSize = shellcodebytes.size();
                shellcodebytes.resize(oldSize + section.SizeOfRawData, 0x00);
                sym_mapped[pSymName] = oldSize;

                memcpy(shellcodebytes.data() + oldSize,
                    static_cast<size_t>(section.PointerToRawData) + std::get<obj*>(sym)->getBuffer(),
                    section.SizeOfRawData);

                if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                    memset(shellcodebytes.data() + oldSize, 0x00, section.SizeOfRawData);

                section_mapped_info smi{};
                smi.maped_va = oldSize;
                smi.maped_size = section.SizeOfRawData;
                section_mapped[&section] = smi;
                //INF("符号:\"%s\" Va:0x%x/Size:0x%x ", pSymName, oldSize, section.SizeOfRawData);
            }
            // 节已经存在
            else
                sym_mapped[pSymName] = section_mapped[&section].maped_va;

            // 对节进行重定位
            // 遍历重定位表
            for (auto& reloca : std::get<obj*>(sym)->relocations(&section))
            {
                // 获取需要重定位符号
                auto& reloc_symbol = std::get<obj*>(sym)->symbols()[reloca.SymbolTableIndex];
                std::string reloc_name = std::get<obj*>(sym)->getSymbolNameByImageSymble(reloc_symbol);

                // 递归对重定位符号所在节进行重定位
                recursive_lookup_relocations(libs, { &reloc_symbol, std::get<obj*>(sym) }, section_mapped, sym_mapped, shellcodebytes,dir_offset);

                // INF("\t\t\t重定位符号:\"%s\" Va:0x%x", reloc_name.c_str(), sym_mapped[reloc_name]);
#ifdef _WIN64
                INF("reloc symbol name：%s, reloc type：%d", reloc_name.c_str(), reloca.Type);

                if (reloca.Type == IMAGE_REL_AMD64_REL32) {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                            (sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                }
                else if (reloca.Type == IMAGE_REL_AMD64_REL32_1) {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                            (1 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                }
                else if (reloca.Type == IMAGE_REL_AMD64_REL32_2) {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                            (2 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                }
                else if (reloca.Type == IMAGE_REL_AMD64_REL32_3) {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                            (3 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                }
                else if (reloca.Type == IMAGE_REL_AMD64_REL32_4) {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                            (4 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                }
                else if (reloca.Type == IMAGE_REL_AMD64_REL32_5) {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                            (5 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));

                }
#else
                if (reloca.Type == IMAGE_REL_I386_REL32)
                {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) = static_cast<int>(sym_mapped[reloc_name] -
                            (sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));;
                }

                else if (reloca.Type == IMAGE_REL_I386_DIR32)
                {
                    *reinterpret_cast<int*>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                        sym_mapped[pSymName]) = sym_mapped[reloc_name];
                    
                    uint32_t place = (uint32_t)(reloca.VirtualAddress + sym_mapped[pSymName]);
                    dir_offset.push_back(place);
                }

#endif // _WIN64
            }
        }

        // 此符号不表示节名，符号存在于节内
        else {
            // 通过value获取节内符号偏移
            if (section_mapped.find(&section) != section_mapped.end()) {
                auto section_maped_va = section_mapped[&section].maped_va;
                auto _sym_va = std::get<PIMAGE_SYMBOL>(sym)->Value;
                sym_mapped[pSymName] = section_maped_va + _sym_va;
                //IMP("静态数据\"%s\" Va:0x%x", pSymName, sym_mapped[pSymName]);
            }
            // 拷贝节到shellcode，但是还无法判断符号在节内偏移
            else {
                auto oldSize = shellcodebytes.size();
                shellcodebytes.resize(oldSize + section.SizeOfRawData, 0x00);

                memcpy(shellcodebytes.data() + oldSize,
                    static_cast<size_t>(section.PointerToRawData) + std::get<obj*>(sym)->getBuffer(),
                    section.SizeOfRawData);
                if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                    memset(shellcodebytes.data() + oldSize, 0x00, section.SizeOfRawData);
                }
                section_mapped_info smi{};
                smi.maped_va = oldSize;
                smi.maped_size = section.SizeOfRawData;
                section_mapped[&section] = smi;

                recursive_lookup_relocations(libs, { std::get<PIMAGE_SYMBOL>(sym), std::get<obj*>(sym) },
                    section_mapped, sym_mapped, shellcodebytes,dir_offset);
            }
        }

    }
    // 符号来自于外部引用
    else {
        if (std::get<PIMAGE_SYMBOL>(sym)->StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            std::get<PIMAGE_SYMBOL>(sym)->Value > 0) {
            if (sym_mapped.find(pSymName) == sym_mapped.end()) {
                auto oldSize = shellcodebytes.size();
                shellcodebytes.resize(oldSize + std::get<PIMAGE_SYMBOL>(sym)->Value, 0x00);
                sym_mapped[pSymName] = oldSize;
                //IMP("External:\"%s\" Va:0x%x/Size:0x%x", pSymName, oldSize, std::get<PIMAGE_SYMBOL>(sym)->Value);
            }
        }
        else {

            //跨obj调用
            bool canResolve = false;
            for (auto& lib : libs) {
                for (auto& obj : lib.objs()) {
                    obj.walkSymbols([&](IMAGE_SYMBOL& Sym) {
                        if (strcmp(pSymName, obj.getSymbolNameByImageSymble(Sym)) == 0) {
                            if (Sym.SectionNumber > IMAGE_SYM_UNDEFINED ||
                                (Sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL && Sym.Value > 0)) {
                                canResolve = true;
                                recursive_lookup_relocations(libs, { &Sym, &obj }, section_mapped, sym_mapped, shellcodebytes,dir_offset);
                            }
                        }
                        });
                }
            }

            if (!canResolve) {
                ERO("Unresolved symbols \"%s\" ", pSymName);
                throw std::exception("Unresolved symbols");
            }
        }
    }
}

void print_shellcode_hpp_file(std::string                                                    resource_name,
    std::unordered_map<std::string, int>& sym_mapped,
    std::vector<uint8_t>& shellcodebytes,
    std::unordered_map<std::string, std::tuple<PIMAGE_SYMBOL, weaponslib2::obj*>>& export_syms) {
    //打开输出文件
    std::ofstream outFile;
    outFile.open(resource_name + ".hpp", std::ios::out);

    if (outFile.is_open()) {
        //输出头部信息
        outFile << "#pragma once" << std::endl;
        outFile << "#include <cstdint>" << std::endl;
        outFile << "namespace shellcode\n{" << std::endl;

        outFile << "namespace rva\n{" << std::endl;

        for (auto& iter : export_syms) {
#ifdef _M_IX86 // 32位模式下 编译器会在函数前面加一个 _
            uint32_t    maped_va = sym_mapped[iter.first];
            std::string exp = iter.first;
            if (exp.front() == '_') {
                exp.erase(exp.begin());
            }
            outFile << "const size_t " << exp << " = 0x" << std::hex << maped_va + 0x4 << ";\n";
#else
            outFile << "const size_t " << iter.first << " = 0x" << std::hex << sym_mapped[iter.first] << ";\n";
#endif // _M_IX86
        }
        outFile << "\n}\n" << std::endl;

        outFile << "unsigned char " + resource_name + " [] = " << std::endl;
        outFile << "\t{" << std::endl << "\t";

        for (size_t idx = 0; idx < shellcodebytes.size(); idx++) {
            if (idx % 80 == 0)
                outFile << "\n";
            uint8_t code_byte = shellcodebytes[idx];
            outFile << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)code_byte << ",";
        }

        outFile << "\t};" << std::endl;

        outFile << "\n};\n" << std::endl;
        outFile.close();
    }
    else {
        throw std::exception("Cannot open hpp file!");
    }
}

void recursive(const char* exp, obj& obj, tcb::span<IMAGE_SECTION_HEADER>& sections, std::vector<std::string>symname)
{
    auto it = std::find(symname.begin(), symname.end(), exp);

    if (it != symname.end())
        return;

    symname.push_back(exp);

    IMAGE_SYMBOL* img = obj.getImageSymbleBySymbolName(exp);

    IMP("-----------------------------------------------------------------------------");

    // 符号存在于某个节中
    if (img->SectionNumber > 0)
    {
        // 找到节头
        auto& sechdr = sections[img->SectionNumber - 0x1];

        // 获取节的重定位
        for (auto& reloc : obj.relocations(&sechdr))
        {
            // 重定位符号
            auto relocImageSymble = obj.symbols()[reloc.SymbolTableIndex];
            // 重定位符号名
            const char* relocSymbolName = obj.getSymbolNameByImageSymble(relocImageSymble);
            INF("节名：%s 重定位RVA: 0x%x 重定位到符号：%s 重定位类型：%d", sechdr.Name, reloc.VirtualAddress, relocSymbolName, reloc.Type);
            recursive(relocSymbolName, obj, sections, symname);
        }
    }

}