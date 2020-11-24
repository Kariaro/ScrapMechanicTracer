package sm.hardcoded.plugin.tracer;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
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
	
	public Varnode getVarnode(String spaceName, int offset, int size) {
		AddressFactory factory = getAddressFactory();
		if(factory == null) return null;
		return new Varnode(factory.getAddressSpace(spaceName).getAddress(offset), size);
	}
	
	public Varnode[] getInputs(PcodeOp op, NodeFunction node) {
		Varnode[] inputs = op.getInputs().clone();
		
		for(int i = 0; i < inputs.length; i++) {
			Varnode varnode = inputs[i];
			if(varnode.isRegister()) {
				FunctionPrototype fp = varnode.getHigh().getHighFunction().getFunctionPrototype();
				
				for(int j = 0; j < fp.getNumParams(); j++) {
					String str_0 = varnode.toString();
					String str_1 = fp.getParam(j).getRepresentative().toString();
					
					if(str_0.equals(str_1)) {
						inputs[i] = node.parameters[j];
						break;
					}
				}
			}
		}
		
		return inputs;
	}
	
	
	
	static class TracedFunction {
		Long minimum_args;
		Long maximum_args;
		String sandbox;
		
		Map<Long, List<String>> bad_args;
		Map<Long, List<String>> args;
		
		TracedFunction() {
			bad_args = new HashMap<>();
			args = new HashMap<>();
		}
		
		void addType(long id, String type) {
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
		
		public String getArgumentString() {
			if((minimum_args == maximum_args) && minimum_args == null) return "";
			
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
		
		public String prettify(String name) {
			String last = name.substring(1);
			
			// This is a hack
			if(name.equals("guiinterface")) return "GuiInterface";
			if(name.equals("aistate")) return "AiState";
			if(name.equals("pathnode")) return "PathNode";
			if(name.equals("areatrigger")) return "AreaTrigger";
			if(name.equals("raycastresult")) return "RaycastResult";
			
			return Character.toUpperCase(name.charAt(0)) + last;
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
			System.out.println("----- " + toString());
			for(int i = 0; i < parameters.length; i++) {
				System.out.printf("    %2d: %s\n", i, parameters[i]);
			}
		}
		
		public String toString() {
			return "(" + address + ", " + searchFurther + ", " + Integer.toHexString(luaParamIndex) + ")";
		}
	}
	

}
