package sm;

import java.io.Serializable;

import ghidra.program.model.listing.Function;
import sm.complex.AnalysedFunction;
import sm.complex.ScrapMechanic;
import sm.util.FunctionUtil;
import sm.util.LuaReg;

public class SMFunctionObject implements Serializable {
	private static final long serialVersionUID = 3187779733238319470L;
	
	private String functionAddress;
	private String name;
	
	private boolean local;
	
	
	/**
	 * This object will contain the data found by exploring
	 * the functions. This data can be serialized.
	 */
	private AnalysedFunction analysedFunction;
	
	public SMFunctionObject(LuaReg reg, boolean local) {
		this.functionAddress = reg.func;
		this.name = reg.name;
		this.local = local;
	}
	
	public String getName() {
		return name;
	}
	
	public Function getFunction() {
		return FunctionUtil.getFunctionAt(functionAddress);
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
	public AnalysedFunction getFuzzedFunction() {
		return analysedFunction;
	}
	
	public void setAnalysedFunction(AnalysedFunction function) {
		this.analysedFunction = function;
	}
	
	// TODO: Show more information about what errors this function has
	//       'Sandbox Violation' client/server
	//
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if(ScrapMechanic.SHOW_ADDRESS) sb.append(functionAddress).append(" -> ");
		if(analysedFunction != null) {
			if(analysedFunction.isRemoved()) {
				sb.append("[REMOVED] ");
			}
		}
		
		sb.append(local ? "[userdata] ":"function ")
		  .append(name);
		
		if(analysedFunction != null) {
			if(!analysedFunction.isRemoved()) {
				sb.append(analysedFunction.toString());
			} else {
				sb.append("( )");
			}
		} else {
			sb.append("( Function was not analysed )");
		}
		
		return sb.toString();
	}
}
