#include "ruleset_resolver.hpp"
#include "../utils/memory.hpp"

namespace scanner
{
	auto ruleset_resolver::resolve( std::uint64_t ruleset_id ) -> std::string
	{
		const auto base = utils::memory::get_module_base( );
		if ( !base ) return {};

		auto* const ctx = reinterpret_cast< void* >( base + ctx_rva );
		const auto get_ruleset_string = reinterpret_cast< get_ruleset_string_fn >( base + get_ruleset_string_rva );

		std::string name;
		get_ruleset_string( ctx, &name, ruleset_id );
		return name;
	}
}