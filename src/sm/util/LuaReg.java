package sm.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * This is the object read from an {@link LuaRegList}
 * 
 *<pre>struct lua_Ref {
 *    char* name;
 *    lua_CFunction func;
 *}</pre>
 *
 * @author HardCoded
 */
public class LuaReg {
	public final String base;
	
	public final String name;
	public final String func;
	
	public LuaReg(String base, String name, String func) {
		this.base = base;
		this.name = name;
		this.func = func;
	}
	
	public Address getBase() {
		return Util.getAddress(base);
	}
	
	public String getName() {
		return name;
	}
	
	public Function getFunction() {
		return Util.getFunctionAt(func);
	}
	
	@Override
	public String toString() {
		return new StringBuilder().append(name).append(" [ ").append(func).append(" ]").toString();
	}
}