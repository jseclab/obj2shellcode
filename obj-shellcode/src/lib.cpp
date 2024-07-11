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

				// NumberOfAuxSymbols ���Ӽ�¼�������� Ҳ���Ǳ� symbol ����ĸ���symbol������
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

				// һ�����������������������������(�ض�λ��Ϣ)���� 65535 ʱ ����� if ����Ч
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
		// �������з���
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
		// ��ȡlib�ļ�
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
			first += sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);//ȥ��ͷ����ʣ�µľ���Obj(COFF��ʽ)

			//ע�⣺BYTE Size[10];Ҫ��atol((LPSTR)..)���ַ������ܵõ���ȷsize
			size_t objSize = atol((LPSTR)pAME->Size);
			m_objs.push_back({ first, objSize });

			first += objSize;
			//ע�⣺������Ա֮���п�������\n����,��PE COFF �ļ���ʽ���в�û���ᵽ
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
		//ͨ���ж����Ƿ��ж̸�ʽ��Ա���ж����Ƿ��ǵ�����ʽ
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
		//��һ����������Ա
		uint8_t* pSect = m_buffer.data() + IMAGE_ARCHIVE_START_SIZE;
		
		if (!pSect)return nullptr;
		
		while (pSect)
		{
			//�ڶ�����������Ա
			if (memcmp(((PIMAGE_ARCHIVE_MEMBER_HEADER)pSect)->Name, IMAGE_ARCHIVE_LINKER_MEMBER, 16) == 0)
			{
				//Nothing
			}
			//�����������Ƴ�Ա
			else if (memcmp(((PIMAGE_ARCHIVE_MEMBER_HEADER)pSect)->Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16) == 0)//LONG Name
			{
				//Nothing
				//���ܳ����Ƴ�Ա��ͷ��������ڣ���������ȴ����Ϊ�ա�
			}
			else //First Obj Section
			{
				return pSect;
			}
			//ע��BYTE Size[10];Ҫ��atol((LPSTR)..)���ַ������ܵõ���ȷsize
			PIMAGE_ARCHIVE_MEMBER_HEADER pAME = (PIMAGE_ARCHIVE_MEMBER_HEADER)pSect;
			pSect += atol((LPSTR)pAME->Size) + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
			//������Ա֮���п�������\n����
			if (*pSect == '\n') pSect++;

			iCtrl++;//��ֹ���������Lib�ļ�����������ѭ��
			if (iCtrl > 3)
			{
				break;
			}
		}
		return nullptr;
	}

}