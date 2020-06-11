package sm;
import java.io.Serializable;

import ghidra.program.model.listing.Function;
import sm.complex.FuzzedFunction;
import sm.complex.ScrapMechanic;
import sm.util.LuaReg;
import sm.util.Util;

public class SMFunctionObject implements Serializable {
	private static final long serialVersionUID = 3187779733238319470L;
	
	private String functionAddress;
	private String name;
	
	private boolean local;
	
	
	/**
	 * This object will contain the data found by exploring
	 * the functions. This data can be serialized.
	 */
	private FuzzedFunction fuzzed;
	
	public SMFunctionObject(LuaReg reg, boolean local) {
		this.functionAddress = reg.func;
		this.name = reg.name;
		this.local = local;
	}
	
	public String getName() {
		return name;
	}
	
	public Function getFunction() {
		return Util.getFunctionAt(functionAddress);
	}
	
	public String getFunctionAddressString() {
		return functionAddress;
	}
	
	/**
	 * This object will contain the data found by exploring
	 * the functions. This data can be serialized.
	 * 
	 * @return The decompiled version of this function
	 */
	public FuzzedFunction getFuzzedFunction() {
		return fuzzed;
	}
	
	public void setFuzzedFunction(FuzzedFunction fuzzed) {
		this.fuzzed = fuzzed;
	}
	
	// TODO: Show more information about what errors this function has
	//       'Sandbox Violation' client/server
	//       ...
	//
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if(ScrapMechanic.SHOW_ADDRESS) sb.append(functionAddress).append(" -> ");
		if(fuzzed != null) {
			if(fuzzed.isRemoved()) {
				sb.append("[REMOVED] ");
			}
		}
		
		sb.append(local ? "[userdata] ":"function ")
		  .append(name);
		
		if(fuzzed != null) {
			if(!fuzzed.isRemoved()) {
				sb.append(fuzzed.toString());
			} else {
				sb.append("( )");
			}
		} else {
			sb.append("( Fuzzed is NULL )");
		}
		
		return sb.toString();
	}
}
