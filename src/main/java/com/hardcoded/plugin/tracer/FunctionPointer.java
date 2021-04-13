package com.hardcoded.plugin.tracer;

import ghidra.program.model.address.Address;

/**
 * A function pointer
 * 
 * @author HardCoded
 * @since 0.1.0
 */
class FunctionPointer {
	public final StringPointer stringPointer;
	public final Address entry;
	public final Address location;
	public final String name;
	
	public FunctionPointer(StringPointer string, Address entry, Address location) {
		this.stringPointer = string;
		this.entry = entry;
		this.location = location;
		
		name = string.str;
	}
}
