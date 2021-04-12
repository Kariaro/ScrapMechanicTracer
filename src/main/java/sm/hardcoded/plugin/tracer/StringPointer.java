package sm.hardcoded.plugin.tracer;

import ghidra.program.model.address.Address;

class StringPointer {
	public final Address addr;
	public final String str;
	
	public StringPointer(Address addr, String str) {
		this.addr = addr;
		this.str = str;
	}
	
	@Override
	public String toString() {
		return addr + ":" + str;
	}
}
