package sm.hardcoded.plugin.tracer;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;

class CodeSyntaxTreeUtils {
	final ScrapMechanicPlugin plugin;
	public CodeSyntaxTreeUtils(ScrapMechanicPlugin tool) {
		this.plugin = tool;
	}
	
	public AddressFactory getAddressFactory() {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return null;
		return currentProgram.getAddressFactory();
	}
	
	public Address getAddress(Varnode varnode) {
		if(varnode == null) return null;
		return getAddress(varnode.getOffset());
	}
	
	public Address getAddress(long offset) {
		AddressFactory factory = getAddressFactory();
		if(factory == null) return null;
		return factory.getAddress(Long.toHexString(offset));
	}
	
	public ExternalLocation getExternalLocation(Varnode varnode) {
		if(varnode == null) return null;
		
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return null;
		
		ProgramMemory memory = plugin.getProgramMemory();
		AddressFactory factory = currentProgram.getAddressFactory();
		String hex = Long.toHexString(varnode.getOffset());
		
		Address readAddress = memory.readAddress(factory.getAddress(hex));
		ExternalLocationIterator iter = currentProgram.getExternalManager().getExternalLocations(readAddress);
		if(!iter.hasNext()) return null;
		return iter.next();
	}
	
	public Varnode resolveUnique(Varnode varnode) {
		if(varnode == null) return null;
		
		PcodeOp def = varnode.getDef();
		if(def == null) return null;
		
		switch(def.getOpcode()) {
			case PcodeOp.COPY: return def.getInput(0);
			case PcodeOp.PTRSUB: return def.getInput(1); // This works sometimes but make sure this is true for all cases.
			default: {
				System.out.println("resolveUnique: Unresolved opcode '" + def.getMnemonic() + "'");
			}
		}
		
		return null;
	}
	
	public String resolveUniqueString(Varnode varnode) {
		Varnode node = resolveUnique(varnode);
		if(node == null) return null;
		return plugin.getProgramMemory().readTerminatedString(getAddress(node));
	}
	
	
	
	static class TracedFunction {
		Long minimum_args;
		Long maximum_args;
		String sandbox;
		
		Map<Long, List<String>> args;
		TracedFunction() {
			args = new HashMap<>();
		}
		
		void addType(long id, String type) {
			if(id > 32); // Remove these
			List<String> list = args.get(id);
			if(list == null) {
				list = new ArrayList<>();
				list.add(type);
				args.put(id, list);
			} else if(!list.contains(type)) {
				list.add(type);
			}
		}
		
		
		public String getArgsString() {
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
		
		public String toString() {
			String map = args.toString();
			map = map.replace("{", "").replace("}", "")
			.replace("], ", "]\n\t");
			
			return String.format(
				"%s\n(\n\t%s\n) (%s) : %s",
				super.toString(),
				map,
				getSandbox(),
				getArgsString()
			);
		}
	}
	
	static class NodeFunction {
		Address address;
		boolean searchFurther;
		int luaParamIndex;
		
		NodeFunction(Address address, boolean searchFurther, int luaParamIndex) {
			this.address = address;
			this.searchFurther = searchFurther;
			this.luaParamIndex = luaParamIndex;
		}
		
		@Override
		public String toString() {
			return "(" + address + ", " + searchFurther + ", " + Integer.toHexString(luaParamIndex) + ")";
		}
	}
	

}
