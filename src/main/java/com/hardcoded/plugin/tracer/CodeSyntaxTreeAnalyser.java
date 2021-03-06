package com.hardcoded.plugin.tracer;

import java.util.*;

import com.hardcoded.plugin.Logger;
import com.hardcoded.plugin.ScrapMechanicPlugin;
import com.hardcoded.plugin.tracer.LuaTypeManager.Type;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

// TODO: Check the content of MULTIEQUAL PcodeOp types

public class CodeSyntaxTreeAnalyser {
	protected final ScrapMechanicPlugin plugin;
	protected final LuaTypeManager typeManager;
	
	public CodeSyntaxTreeAnalyser(ScrapMechanicPlugin tool, LuaTypeManager typeManager) {
		this.plugin = tool;
		this.typeManager = typeManager;
	}
	
	protected Program currentProgram;
	protected ProgramMemory programMemory;
	protected AddressFactory addressFactory;
	protected FunctionManager functionManager;
	protected ExternalManager externalManager;
	protected Varnode stackVarnode;
	private Map<Long, ExternalLocation> externalLocationCache;
	
	protected void init() {
		currentProgram = Objects.requireNonNull(plugin.getCurrentProgram(), "plugin.getCurrentProgram() was null");
		programMemory = Objects.requireNonNull(plugin.getProgramMemory(), "plugin.getProgramMemory() was null");
		addressFactory = Objects.requireNonNull(currentProgram.getAddressFactory(), "currentProgram.getAddressFactory() was null");
		functionManager = Objects.requireNonNull(currentProgram.getFunctionManager(), "currentProgram.getFunctionManager() was null");
		externalManager = Objects.requireNonNull(currentProgram.getExternalManager(), "currentProgram.getExternalManager() was null");
		
		stackVarnode = getVarnode("stack", 0x4, 4);
		externalLocationCache = new HashMap<>();
	}
	
	// TODO: Make sure that this function is only run once for each function.
	protected boolean discoverCode(Address entry) {
		Function function = functionManager.getFunctionAt(entry);
		
		if(function == null) {
			DisassembleCommand cmd = new DisassembleCommand(entry, null, true);
			cmd.enableCodeAnalysis(false);
			if(!cmd.applyTo(currentProgram)) {
				Msg.warn(this, "Failed to disassemble memory at address '" + entry + "'");
			}
			
			function = functionManager.getFunctionAt(entry);
			
			if(function == null) {
				CreateFunctionCmd cfcmd = new CreateFunctionCmd(entry);
				
				if(!cfcmd.applyTo(currentProgram, TaskMonitor.DUMMY)) {
					Msg.error(this, "(1) Failed to create function at address '" + entry + "'");
					Msg.error(this, "MESSAGE: " + cfcmd.getStatusMsg());
					return false;
				} else {
					function = cfcmd.getFunction();
				}
				
				if(function == null) {
					Msg.error(this, "(2) Failed to create function at address '" + entry + "'");
					Msg.error(this, "MESSAGE: " + cfcmd.getStatusMsg());
					return false;
				}
			}
		}
		
		return true;
	}
	
	protected Address getAddress(Varnode varnode) {
		if(varnode == null) return null;
		return getAddress(varnode.getOffset());
	}
	
	protected Address getAddress(String str) {
		return addressFactory.getAddress(str);
	}
	
	protected Address getAddress(long offset) {
		return addressFactory.getAddress(Long.toHexString(offset));
	}
	
	// TODO: Maybe cache all lua functions before we start the analysis.
	// What if this causes threads to slowdown or become inconsistent?
	protected ExternalLocation getExternalLocation(Varnode varnode) {
		if(varnode == null) return null;
		long offset = varnode.getOffset();
		
		ExternalLocation location = externalLocationCache.get(offset);
		if(location == null) {
			Address readAddress = programMemory.readAddress(getAddress(offset));
			ExternalLocationIterator iter = externalManager.getExternalLocations(readAddress);
			if(!iter.hasNext()) return null;
			location = iter.next();
			externalLocationCache.put(offset, location);
			return location;
		}
		
		return location;
	}
	
	protected Varnode resolveUnique(Varnode varnode) {
		if(varnode == null) return null;
		
		PcodeOp def = varnode.getDef();
		if(def == null) return null;
		
		switch(def.getOpcode()) {
			case PcodeOp.COPY: return def.getInput(0);
			case PcodeOp.PTRSUB: return def.getInput(1); // This works sometimes but make sure this is true for all cases.
			default: {
				// ??? Branches probably
				// Logger.log("resolveUnique: Unresolved opcode '%s'", def.getMnemonic());
			}
		}
		
		return null;
	}
	
	protected String resolveConstantString(Varnode varnode) {
		if(varnode == null || !varnode.isConstant()) return null;
		return programMemory.readTerminatedString(getAddress(varnode));
	}
	
	protected String resolveConstantStringNoNull(Varnode varnode) {
		if(varnode == null || !varnode.isConstant()) return "";
		String str = programMemory.readTerminatedString(getAddress(varnode));
		return str == null ? "":str;
	}
	
	protected Varnode getVarnode(String spaceName, int offset, int size) {
		return new Varnode(addressFactory.getAddressSpace(spaceName).getAddress(offset), size);
	}
	
	protected Varnode[] getInputs(PcodeOp op, NodeFunction node) {
		Varnode[] inputs = op.getInputs().clone();
		FunctionPrototype fp = node.high.getFunctionPrototype();
		
		for(int i = 0; i < inputs.length; i++) {
			Varnode varnode = inputs[i];
			if(varnode.isConstant()) continue;
			
			String str_0 = varnode.toString();
			for(int j = 0; j < Math.min(node.parameters.length, fp.getNumParams()); j++) {
				Varnode var = fp.getParam(j).getHighVariable().getRepresentative();
				String str_1 = var.toString();
				
				if(str_0.equals(str_1)) {
					inputs[i] = node.parameters[j];
					break;
				}
			}
		}
		
		for(int i = 0; i < inputs.length; i++) {
			Varnode varnode = inputs[i];
			if(varnode.isRegister()) {
				PcodeOp def = varnode.getDef();
				
				// What if we get stuck in a loop????
				if(def != null) {
					Varnode replace = null;
					switch(def.getOpcode()) {
						case PcodeOp.CAST: replace = def.getInput(0); break;
						case PcodeOp.INT_ZEXT: replace = def.getInput(0); break;
						case PcodeOp.FLOAT_TRUNC: replace = def.getInput(0); break;
						default: {
							// ????
						}
					}
					
					if(replace != null) {
						inputs[i] = replace;
						i--;
						continue;
					}
				}
			}
			
			if(varnode.isUnique()) {
				PcodeOp def = varnode.getDef();
				
				if(def != null) {
					Varnode replace = null;
					switch(def.getOpcode()) {
						case PcodeOp.COPY: replace = def.getInput(0); break;
						case PcodeOp.CAST: replace = def.getInput(0); break;
						case PcodeOp.PTRSUB: replace = def.getInput(1); break;
						default: {
							// ??? Branches probably
						}
					}
					
					if(replace != null) {
						inputs[i] = replace;
						i--;
						continue;
					}
				}
			}
		}
		
		return inputs;
	}
	
	
	
	public static class TracedFunction {
		Long minimum_args;
		Long maximum_args;
		String sandbox;
		
		Map<Long, List<String>> bad_args;
		Map<Long, List<String>> args;
		List<String> returns;
		
		public TracedFunction() {
			bad_args = new HashMap<>();
			args = new HashMap<>();
			returns = new ArrayList<>();
		}
		
		public void setMinimumArgs(Long min) {
			this.minimum_args = min;
		}
		
		public void setMaximumArgs(Long max) {
			this.maximum_args = max;
		}
		
		public void setSandbox(String sandbox) {
			this.sandbox = sandbox;
		}
		
		public void addType(long id, String type) {
			if(id < 1 || id > 32) {
				addBadType(id, type);
				return;
			}
			
			List<String> list = args.get(id);
			if(list == null) {
				list = new ArrayList<>();
				list.add(type);
				args.put(id, list);
			} else if(!list.contains(type)) {
				list.add(type);
			}
		}
		
		void addType(long id, Type type) {
			if(type == null) return;
			addType(id, type.getName().toLowerCase());
		}
		
		// Keep bad types that was added but do not show them to the user
		void addBadType(long id, String type) {
			List<String> list = bad_args.get(id);
			if(list == null) {
				list = new ArrayList<>();
				list.add(type);
				bad_args.put(id, list);
			} else if(!list.contains(type)) {
				list.add(type);
			}
		}
		
		public void addReturn(String type) {
			if(type == null || type.isBlank()) return;
			type = type.toLowerCase();
			if(returns.contains(type)) return;
			returns.add(type);
		}
		
		public String getArgumentString() {
			//if((minimum_args == maximum_args) && minimum_args == null) return "";
			
			long min = 1, max = 1;
			if(minimum_args != null) min = minimum_args;
			if(maximum_args != null) max = maximum_args;
			if((min == max) && min == 0) return "";
			
			for(long i = 0; i < 32; i++) {
				if(args.containsKey(i) && i > max) max = i;
			}
			
			StringBuilder sb = new StringBuilder();
			for(long i = 1; i <= max; i++) {
				List<String> list = args.get(i);
				
				if(list == null) {
					sb.append("---, ");
				} else {
					list = configure(list);
					if(list.size() == 1) {
						sb.append(list.get(0)).append(", ");
					} else {
						sb.append(list).append(", ");
					}
				}
			}
			
			if(sb.length() > 0) sb.deleteCharAt(sb.length() - 2);
			return sb.toString().trim();
		}
		
		private List<String> configure(List<String> list) {
			List<String> result = new ArrayList<>();
			for(String s : list) result.add(prettify(s));
			return result;
		}
		
		private String prettify(String name) {
			String last = name.substring(1);
			
			// This is a hack
			if(name.equals("guiinterface")) return "GuiInterface";
			if(name.equals("aistate")) return "AiState";
			if(name.equals("pathnode")) return "PathNode";
			if(name.equals("areatrigger")) return "AreaTrigger";
			if(name.equals("raycastresult")) return "RaycastResult";
			
			return Character.toUpperCase(name.charAt(0)) + last;
		}
		
		public Long getMinArgs() {
			return minimum_args;
		}
		
		public Long getMaxArgs() {
			return maximum_args;
		}
		
		public String getSizeString() {
			if(minimum_args == null) {
				if(maximum_args == null) {
					return "args(?)";
				} else {
					return "args(?," + maximum_args + ")";
				}
			} else {
				if(maximum_args == null) {
					return "args(" + minimum_args + ",?)";
				} else {
					if(minimum_args != maximum_args) {
						return "args(" + minimum_args + "," + maximum_args + ")";
					}
					
					return "args(" + minimum_args + ")";
				}
			}
		}
		
		public String getSandbox() {
			if(sandbox == null) return "";
			return sandbox;
		}
		
		public List<String> getArgument(long min) {
			return args.get(min);
		}

		public List<String> getReturnTypes() {
			return returns;
		}
		
		public String toString() {
			String map = args.toString();
			map = map.replace("{", "").replace("}", "")
			.replace("], ", "]\n\t");
			
			return String.format(
				"%s\n(\n\t%s\n) (%s) : %s",
				super.toString(),
				map,
				getSandbox(),
				getSizeString()
			);
		}
	}
	
	static class NodeFunction {
		Address address;
		boolean searchFurther;
		int luaParamIndex;
		Varnode[] parameters;
		HighFunction high;
		
		NodeFunction(Address address, int index, Varnode... parameters) {
			this(address, index >= 0, index, parameters);
		}
		
		NodeFunction(Address address, boolean searchFurther, int index, Varnode... parameters) {
			this.address = address;
			this.searchFurther = searchFurther;
			this.luaParamIndex = index;
			this.parameters = parameters;
		}
		
		public void dump() {
			Logger.log("----- " + toString());
			for(int i = 0; i < parameters.length; i++) {
				Logger.log("    %2d: %s\n", i, parameters[i]);
			}
		}
		
		public String toString() {
			return "(" + address + ", " + searchFurther + ", " + Integer.toHexString(luaParamIndex) + ")";
		}
	}
}
