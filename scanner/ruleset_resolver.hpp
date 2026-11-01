#pragma once

#include <cstdint>
#include <string>

namespace scanner
{
	class ruleset_resolver
	{
	public:
		static auto resolve( std::uint64_t ruleset_id ) -> std::string;

	private:
		// current calling conv : RCX=ctx, RDX=&out, R8=ruleset_id, might change, just put bp on it and inspect regs if it does
		using get_ruleset_string_fn = void( * )( void* ctx, std::string* out, std::uint64_t ruleset_id );
		static constexpr std::uintptr_t ctx_rva = 0x8D1D3E8;
		static constexpr std::uintptr_t get_ruleset_string_rva = 0x4F11F60;
	};
}