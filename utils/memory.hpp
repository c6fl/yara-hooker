#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace utils
{
	class memory
	{
	public:
		static auto get_module_base(const std::string& mod = {}) -> std::uintptr_t;
		static auto install_hook(std::uintptr_t target, void* detour, std::size_t psize, std::vector<std::uint8_t>& o_out ) -> void*;
		static auto decrypt_fix(std::uintptr_t address, const std::vector<std::uint8_t>& signature, std::uint32_t too_long) -> bool;
	};
}