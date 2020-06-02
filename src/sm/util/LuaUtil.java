package sm.util;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;

public final class LuaUtil {
	private static final String LIBRARY_NAME = "LUA51.DLL";
	private static HashSet<String> lua_functions = new HashSet<>();
	private static Map<String, Address> name_to_address = new HashMap<>();
	private static Map<Address, String> address_to_name = new HashMap<>();
	private static Map<String, Function> name_to_function = new HashMap<>();
	private static Map<Address, Function> external_functions = new HashMap<>();
	
	
	private static Map<String, Type> TYPES = new HashMap<>();
	
	private LuaUtil() {
	}
	
	public static void init(GhidraScript ghidra) {
		lua_functions.clear();
		name_to_address.clear();
		address_to_name.clear();
		external_functions.clear();
		name_to_function.clear();
		
		Type[] lua_default = {
			new Type("none", -1),
			new Type("nil", 0),
			new Type("boolean", 1),
			new Type("lightuserdata", 2),
			new Type("number", 3),
				new Type("integer", 3),
			
			new Type("string", 4),
			new Type("table", 5),
			new Type("function", 6),
			new Type("userdata", 7),
			new Type("thread", 8)
		};
		
		for(Type type : lua_default) {
			TYPES.put(type.name, type);
		}
		
		Program program = ghidra.getCurrentProgram();
		ExternalManager externalManager = program.getExternalManager();
		//Library library = externalManager.getExternalLibrary(LIBRARY_NAME);
		//System.out.println("FoundLibrary: " + library);
		//SymbolTable table = program.getSymbolTable();
		//System.out.println("Library: tble = " + table);
		//SymbolIterator symbolIterator = table.getChildren(library.getSymbol());
		//System.out.println("Library: syit = " + symbolIterator);
		
		{
			ExternalLocationIterator iterator = externalManager.getExternalLocations(LIBRARY_NAME);
			do {
				ExternalLocation location = iterator.next();
				//System.out.println("    location = " + location);
				
				if(location.isFunction()) {
					Function function = location.getFunction();
					//System.out.println("        function = " + function);
					//System.out.println("        callspec = " + function.getCallingConventionName());
					//System.out.println("        parameters = " + function.getParameterCount());
					/*Parameter[] parameters = function.getParameters();
					for(int i = 0; i < parameters.length; i++) {
						System.out.println("            " + i + ": " + parameters[i]);
					}*/
					
					String name = function.getName(false);
					Address address = location.getAddress();
					//System.out.println("        location = " + address);
					//System.out.println("        location = " + function.getExternalLocation().getAddress());
					
					name_to_address.put(name, address);
					address_to_name.put(address, name);
					lua_functions.add(name);
					name_to_function.put(name, function);
				}
				//System.out.println();
			} while(iterator.hasNext());
		}
		
		
		// TODO: Try fix this
		/*
		{
			ProjectData projectData = ghidra.getState().getProject().getProjectData();
			DomainFile file = projectData.getFile(library.getAssociatedProgramPath());
			
			Program libraryProgram = null;
			try {
				libraryProgram = (Program)file.getImmutableDomainObject(
					ghidra,
					DomainFile.DEFAULT_VERSION,
					ghidra.getMonitor()
				);
			} catch (VersionException e) {
				Util.printStackTrace(e);
			} catch(CancelledException e) {
				Util.printStackTrace(e);
			} catch(IOException e) {
				Util.printStackTrace(e);
			}
			
			FunctionManager functionManager = libraryProgram.getFunctionManager();
			FunctionIterator functionIterator = functionManager.getFunctions(true);
			
			do {
				Function function = functionIterator.next();
				
				String name = function.getName(false);
				if(lua_functions.contains(name)) {
					Function current = name_to_function.get(name);
					
					FunctionReturnTypeFieldLocation loc_0 = (FunctionReturnTypeFieldLocation)current.getSymbol().getProgramLocation();
					FunctionReturnTypeFieldLocation loc_1 = (FunctionReturnTypeFieldLocation)function.getSymbol().getProgramLocation();
					
					// TODO: Find a better solution
					if(!loc_0.getSignature().equals(loc_1.getSignature())) {
						//System.out.println("  current = " + loc_0.getSignature());
						//System.out.println("  target  = " + loc_1.getSignature());
						
						try {
							current.updateFunction(
								function.getCallingConventionName(),
								function.getReturn(),
								FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
								false,
								SourceType.ANALYSIS,
								function.getParameters()
							);
							current.setVarArgs(function.hasVarArgs());
						} catch(DuplicateNameException e) {
							Util.printStackTrace(e);
						} catch(InvalidInputException e) {
							Util.printStackTrace(e);
						}
					}
					
				}
			} while(functionIterator.hasNext());
		}
		*/
	}
	
	public static boolean isLuaFunction(String name) {
		if(name.startsWith(LIBRARY_NAME)) {
			return lua_functions.contains(name.substring(LIBRARY_NAME.length() + 2));
		}
		return lua_functions.contains(name);
	}
	
	public static Map<String, Type> getTypes() {
		return TYPES;
	}
	
	public static Address getExternalAddressFromName(String name) {
		return name_to_address.getOrDefault(name, null);
	}
	
	public static String getNameFromExternalAddress(Address address) {
		return address_to_name.getOrDefault(address, null);
	}
	
	public static String getNameFromPointerAddress(Address address) {
		Address addr = Util.getAddressPointer(address);
		if(addr == null) return null;
		return address_to_name.getOrDefault(addr, null);
	}
	
	
	public static boolean isLuaFunctionPointer(Address address) {
		Address addr = Util.getAddressPointer(address);
		boolean check = address_to_name.containsKey(addr);
		/*if(check) {
			// Try fix the method if it's not already done
			Function external = external_functions.getOrDefault(addr, null);
			if(external != null) {
				Function current = Util.getScript().getFunctionAt(address);
				
				System.out.println("func = " + current);
				System.out.println("addr = " + address);
				try {
					current.updateFunction(
						external.getCallingConventionName(),
						external.getReturn(),
						FunctionUpdateType.CUSTOM_STORAGE,
						false,
						SourceType.ANALYSIS,
						external.getParameters()
					);
				} catch(DuplicateNameException e) {
					Util.printStackTrace(e);
				} catch(InvalidInputException e) {
					Util.printStackTrace(e);
				}
				
				//current.addParameter(Variable.class, source)
			}
		}*/
		
		return check;
	}
	
	public static void addType(String name, int id) {
		String type_name = name.toLowerCase();
		if(TYPES.containsKey(type_name)) {
			TYPES.get(type_name).id = id;
		} else {
			Type type = new Type(type_name, id);
			TYPES.put(type_name, type);
		}
	}
	
	public static void addType(Address address) throws MemoryAccessException {
		Address addr = Util.getAddressFromPointer(address);
		String name = Util.readTerminatedString(addr);
		int id = Util.readInt(address.add(4), true);
		
		// System.out.println("type -> " + address + " n:\"" + name +"\" i:" + Integer.toHexString(id));
		if(name != null) {
			addType(name, id);
		}
	}
	
	public static Type getType(String name) {
		String type_name = name.toLowerCase();
		if(TYPES.containsKey(type_name)) {
			return TYPES.get(type_name);
		}
		
		Type type = new Type(type_name, Integer.MIN_VALUE);
		TYPES.put(type_name, type);
		return type;
	}
	
	public static String getTypeNameFromId(long id) {
		for(Type type : TYPES.values()) {
			if(type.id == id) return type.name;
		}
		return null;
	}
	
	public static class Type implements Serializable {
		private static final long serialVersionUID = 4504853564961652716L;
		
		private String name;
		private int id;
		
		private Type(String name, int id) {
			this.name = name;
			this.id = id;
		}
		
		public String getName() {
			return name;
		}
		
		public String getPrettyName() {
			String last = name.substring(1);
			// This is a little cheat for pretty print :D
			if(name.equals("guiinterface")) return "GuiInterface";
			if(name.equals("aistate")) return "AiState";
			if(name.equals("pathnode")) return "PathNode";
			if(name.equals("areatrigger")) return "AreaTrigger";
			
			return new StringBuilder().append(Character.toUpperCase(name.charAt(0))).append(last).toString();
		}
		
		public int getId() {
			return id;
		}
		
		@Override
		public int hashCode() {
			return name.hashCode();
		}
		
		@Override
		public boolean equals(Object obj) {
			if(obj instanceof Type) {
				return name.equals(((Type)obj).name);
			}
			return false;
		}
		
		@Override
		public String toString() {
			return new StringBuilder().append("(").append(name).append("  id=").append(Integer.toHexString(id)).append(")").toString();
		}
	}
}
