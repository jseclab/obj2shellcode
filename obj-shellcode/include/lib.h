#pragma once

#include "span.hpp"
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <iostream>
#include <functional>
#include <unordered_map>

namespace weaponslib2{


	template <size_t N>
	constexpr bool same_str(const char* str, const char(&str_c)[N]) {
		return (strncmp(str, str_c, N - 1) == 0);
	}
	template <size_t N>
	constexpr bool same_str(const char(&str_c)[N], const char* str) {
		return (strncmp(str, str_c, N - 1) == 0);
	}

	inline
		std::vector<std::string> split_str(const std::string& s, char delim = ' ') {
		std::vector<std::string> tokens;
		auto string_find_first_not = [s, delim](size_t pos = 0) -> size_t {
			for (size_t i = pos; i < s.size(); i++) {
				if (s[i] != delim)
					return i;
			}
			return std::string::npos;
		};
		size_t lastPos = string_find_first_not(0);
		size_t pos = s.find(delim, lastPos);
		while (lastPos != std::string::npos) {
			tokens.emplace_back(s.substr(lastPos, pos - lastPos));
			lastPos = string_find_first_not(pos);
			pos = s.find(delim, lastPos);
		}
		return tokens;
	}


	class obj {
	
	public:
		obj(uint8_t* buffer, size_t size) :m_buffer(buffer), m_size(size) {};
		~obj() {};
		
		uint8_t* getBuffer() { return m_buffer; };

		std::tuple<uint8_t*, size_t>getInfo()
		{
			return { m_buffer,m_size };
		}

		std::vector<std::string>& exports();
		tcb::span<IMAGE_SYMBOL>& symbols();
		tcb::span<IMAGE_SECTION_HEADER>& sections();
		tcb::span<IMAGE_RELOCATION>& relocations(PIMAGE_SECTION_HEADER section_header);

		void walkSymbols(std::function<void(IMAGE_SYMBOL&)> _call);
		const char* getSymbolNameByImageSymble(IMAGE_SYMBOL& symbol);
		IMAGE_SYMBOL* getImageSymbleBySymbolName(std::string symName);

	private:
		size_t m_size;
		uint8_t* m_buffer;
		std::vector<std::string> m_exports;
		tcb::span<IMAGE_SYMBOL> m_symbols;
		tcb::span<IMAGE_SECTION_HEADER> m_sections;
		tcb::span<IMAGE_RELOCATION> empty_relocations;
		std::unordered_map<PIMAGE_SECTION_HEADER, tcb::span<IMAGE_RELOCATION>> m_relocations;
		const char* m_stringT = 0;
	};


	class lib {
	public:

		//lib(std::string&& path);
		lib(std::string path);
		~lib();

		bool isLib();
		std::vector<obj>& objs();

		void printobjs()
		{
			for (auto obj : m_objs)
			{
				auto info = obj.getInfo();
				std::cout << "obj address: " << std::hex << static_cast<void*>(std::get<uint8_t*>(info)) << " obj size: "<< std::get<size_t>(info) << std::endl;
			}
		}

	protected:
		void readLib(const std::string& file);

		uint8_t* getFirstObjSection();
		bool bImportlibraryFormat(uint8_t* pSect);
	private:
		std::vector<uint8_t> m_buffer;
		std::vector<obj> m_objs;
	};
}
