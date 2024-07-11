#include <fstream>
#include <regex>
#include "rang_impl.hpp"
#include "lib.h"


namespace weaponslib2{

	std::vector<std::string>& obj::exports()
	{
		if (m_exports.empty()) 
		{
			PIMAGE_FILE_HEADER obj = reinterpret_cast<PIMAGE_FILE_HEADER>(m_buffer);
			auto               symbols = this->symbols();
			auto               section_headers = this->sections();

			for (size_t idx = 0; idx < symbols.size(); idx++) 
			{
				auto& symbol = symbols[idx];

				if (symbol.SectionNumber > 0) 
				{
					auto& section = section_headers[static_cast<size_t>(symbol.SectionNumber) - 1];

					// IMAGE_SCN_LNK_INFO
					if (same_str((char*)section.Name, ".drectve")) 
					{
						const char* data = section.PointerToRawData + (char*)obj;
						auto strs = split_str(std::string(data, static_cast<size_t>(section.SizeOfRawData)), ' ');
						for (auto str : strs) 
						{
							// msvc /EXPORT:?main2@@YAHXZ
							// llvm /EXPORT:"?main2@@YAHXZ"
							std::smatch base_match;
							if (std::regex_match(str, base_match, std::regex("^(/EXPORT:)(.*?)|(\".*?\")"))) 
							{
								std::string export_name = base_match[2].str();
								
								if (std::regex_match(export_name, base_match, std::regex("^\"(.*?)\""))) 
									export_name = base_match[1].str();
								
								if (std::regex_match(export_name, base_match, std::regex("(.*?),DATA$"))) 
									export_name = base_match[1].str();

								m_exports.push_back(export_name);
							}
						}
					}
				}

				// NumberOfAuxSymbols 附加记录的数量。 也就是本 symbol 后面的附加symbol的数量
				if (symbol.NumberOfAuxSymbols)
					idx += symbol.NumberOfAuxSymbols;
			}
		}
		return m_exports;
	}

	tcb::span<IMAGE_SECTION_HEADER>& obj::sections() {
		if (m_sections.empty()) {
			PIMAGE_FILE_HEADER    obj = reinterpret_cast<PIMAGE_FILE_HEADER>(m_buffer);
			PIMAGE_SECTION_HEADER section_headers =
				reinterpret_cast<PIMAGE_SECTION_HEADER>((byte*)obj + sizeof IMAGE_FILE_HEADER);
			m_sections = tcb::span<IMAGE_SECTION_HEADER>(section_headers, static_cast<std::size_t>(obj->NumberOfSections));
		}
		return m_sections;
	}

	tcb::span<IMAGE_RELOCATION>& obj::relocations(PIMAGE_SECTION_HEADER section_header) {
		auto iter = m_relocations.find(section_header);
		if (iter != m_relocations.end()) {
			return iter->second;
		}
		else { 
			PIMAGE_FILE_HEADER obj = reinterpret_cast<PIMAGE_FILE_HEADER>(m_buffer);
			if (section_header->PointerToRelocations) {
				PIMAGE_RELOCATION reloc_dir = reinterpret_cast<PIMAGE_RELOCATION>(section_header->PointerToRelocations +
					reinterpret_cast<byte*>(obj));

				// 一种特殊情况，单个函数的依赖函数(重定位信息)超过 65535 时 ，这个 if 会生效
				// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
				if (section_header->NumberOfRelocations == 0xffff &&
					(section_header->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)) {
					tcb::span<IMAGE_RELOCATION> relocation(reloc_dir, static_cast<std::size_t>(reloc_dir->RelocCount));
					m_relocations[section_header] = relocation;
					return m_relocations[section_header];
				}

				tcb::span<IMAGE_RELOCATION> relocation(reloc_dir, static_cast<std::size_t>(section_header->NumberOfRelocations));

				m_relocations[section_header] = relocation;
				return m_relocations[section_header];
			}
		}
		return empty_relocations;
	}

	tcb::span<IMAGE_SYMBOL>& obj::symbols()
	{
		if (m_symbols.empty()) {
			PIMAGE_FILE_HEADER obj = reinterpret_cast<PIMAGE_FILE_HEADER>(m_buffer);
			PIMAGE_SYMBOL      symbol_table = reinterpret_cast<PIMAGE_SYMBOL>(obj->PointerToSymbolTable + (byte*)obj);
			m_symbols = tcb::span<IMAGE_SYMBOL>(symbol_table, static_cast<std::size_t>(obj->NumberOfSymbols));
		}
		return m_symbols;
	}

	void obj::walkSymbols(std::function<void(IMAGE_SYMBOL&)> _call) {
		auto& symbols = this->symbols();
		// 遍历所有符号
		for (size_t idx = 0; idx < symbols.size(); idx++) {
			_call(symbols[idx]);
			if (symbols[idx].NumberOfAuxSymbols) {
				idx += symbols[idx].NumberOfAuxSymbols;
			}
		}
	}

	const char* obj::getSymbolNameByImageSymble(IMAGE_SYMBOL& symbol) {

		if (symbol.N.Name.Short != 0)
		{
			char name[9];
			memcpy(name, symbol.N.ShortName, 8);
			size_t length = strnlen(name, 8);
			name[length] = '\0';
			return _strdup(name);
		}
			
		else {
			if (!m_stringT) {
				PIMAGE_FILE_HEADER    obj = reinterpret_cast<PIMAGE_FILE_HEADER>(m_buffer);
				PIMAGE_SECTION_HEADER section_headers =
					reinterpret_cast<PIMAGE_SECTION_HEADER>((byte*)obj + sizeof IMAGE_FILE_HEADER);

				PIMAGE_SYMBOL symbol_table = reinterpret_cast<PIMAGE_SYMBOL>(obj->PointerToSymbolTable + (byte*)obj);

				m_stringT = reinterpret_cast<const char*>(reinterpret_cast<std::uintptr_t>(symbol_table) +
					(obj->NumberOfSymbols * sizeof IMAGE_SYMBOL));
			}
			return (m_stringT + symbol.N.Name.Long);
		}
	}

	IMAGE_SYMBOL* obj::getImageSymbleBySymbolName(std::string symName)
	{
		if (m_symbols.empty())
			this->symbols();

		for (size_t idx = 0; idx < m_symbols.size(); idx++)
		{
			auto& symbol = m_symbols[idx];
			const char* name = this->getSymbolNameByImageSymble(symbol);

			if (name == symName)
				return &symbol;

			if (symbol.NumberOfAuxSymbols)
				idx += symbol.NumberOfAuxSymbols;
		}

		return nullptr;
	}


	lib::lib(std::string path)
	{
		// 读取lib文件
		readLib(path);

		if (m_buffer.size() <= 0)
			ERO("lib initialize faild");
	}

	lib::~lib(){}


	std::vector<obj>& lib::objs()
	{
		m_objs.clear();

		uint8_t* buffer = m_buffer.data();
		size_t size = m_buffer.size();
		uint8_t* first = getFirstObjSection();

		if (first)
		{
			if (bImportlibraryFormat(first + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER)))
				return m_objs;
		}
		else return m_objs;

		do
		{
			PIMAGE_ARCHIVE_MEMBER_HEADER pAME = (PIMAGE_ARCHIVE_MEMBER_HEADER)first;
			first += sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);//去掉头部，剩下的就是Obj(COFF格式)

			//注意：BYTE Size[10];要用atol((LPSTR)..)这种方法才能得到正确size
			size_t objSize = atol((LPSTR)pAME->Size);
			m_objs.push_back({ first, objSize });

			first += objSize;
			//注意：两个成员之间有可能是由\n隔开,《PE COFF 文件格式》中并没有提到
			if (*first == '\n')
				first++;

		} while (first < (buffer + size));

		return m_objs;
	}

	bool lib::isLib() {
		if (strncmp(reinterpret_cast<const char*>(m_buffer.data()), IMAGE_ARCHIVE_START, sizeof IMAGE_ARCHIVE_START - 1))
			return false;
		else
			return true;
	}

	void lib::readLib(const std::string& file)
	{
		std::ifstream fstr(file, std::ios::binary);
		fstr.unsetf(std::ios::skipws);
		fstr.seekg(0, std::ios::end);

		const auto file_size = fstr.tellg();

		fstr.seekg(NULL, std::ios::beg);
		m_buffer.reserve(static_cast<uint32_t>(file_size));
		m_buffer.insert(m_buffer.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
	}

	bool lib::bImportlibraryFormat(uint8_t* pSect)
	{
		//通过判断其是否有短格式成员来判断其是否是导入库格式
		uint16_t Sig1 = *(uint16_t*)(pSect);
		uint16_t Sig2 = *(uint16_t*)(pSect + 2);
		if (Sig1 == IMAGE_FILE_MACHINE_UNKNOWN && Sig2 == 0xffff)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}

	uint8_t* lib::getFirstObjSection()
	{
		int iCtrl = 0;
		//第一个链接器成员
		uint8_t* pSect = m_buffer.data() + IMAGE_ARCHIVE_START_SIZE;
		
		if (!pSect)return nullptr;
		
		while (pSect)
		{
			//第二个链接器成员
			if (memcmp(((PIMAGE_ARCHIVE_MEMBER_HEADER)pSect)->Name, IMAGE_ARCHIVE_LINKER_MEMBER, 16) == 0)
			{
				//Nothing
			}
			//第三个长名称成员
			else if (memcmp(((PIMAGE_ARCHIVE_MEMBER_HEADER)pSect)->Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16) == 0)//LONG Name
			{
				//Nothing
				//尽管长名称成员的头部必须存在，但它本身却可以为空。
			}
			else //First Obj Section
			{
				return pSect;
			}
			//注意BYTE Size[10];要用atol((LPSTR)..)这种方法才能得到正确size
			PIMAGE_ARCHIVE_MEMBER_HEADER pAME = (PIMAGE_ARCHIVE_MEMBER_HEADER)pSect;
			pSect += atol((LPSTR)pAME->Size) + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
			//两个成员之间有可能是由\n隔开
			if (*pSect == '\n') pSect++;

			iCtrl++;//防止遇到错误的Lib文件，而导致死循环
			if (iCtrl > 3)
			{
				break;
			}
		}
		return nullptr;
	}

}