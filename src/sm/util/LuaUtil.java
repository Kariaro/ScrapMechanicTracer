package sm.util;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

// NOTE: Rework this class.. It's ugly
public final class LuaUtil {
	private static final String LIBRARY_NAME = "LUA51.DLL";
	
	private static Map<String, String> addr_to_name;
	private static Map<String, String> name_to_addr;
	private static Map<String, Type> types;
	private static Set<String> functions;
	
	public static void init(GhidraScript ghidra) throws Exception {
		Program program = ghidra.getCurrentProgram();
		SymbolTable table = program.getSymbolTable();
		
		Symbol library = table.getLibrarySymbol(LIBRARY_NAME);
		if(library == null) {
			throw new Exception("Failed to find the library '" + LIBRARY_NAME + "'");
		}
		
		// TODO: Can we initialize the default lua types in another way?
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
		
		types = new HashMap<>();
		for(Type type : lua_default) {
			types.put(type.name, type);
		}
		
		addr_to_name = new HashMap<>();
		name_to_addr = new HashMap<>();
		functions = new HashSet<>();
		
		SymbolIterator iterator = table.getChildren(library);
		while(iterator.hasNext()) {
			Symbol symbol = iterator.next();
			Object object = symbol.getObject();
			
			if(object instanceof Function) {
				Function function = (Function)object;
				ExternalLocation external = function.getExternalLocation();
				
				Function func = (Function)object;
				//System.out.println("    name = " + func.getName());
				//System.out.println("    external = " + external.getAddress());
				
				String addr = external.getAddress().toString();
				String name = func.getName();
				addr_to_name.put(addr, name);
				name_to_addr.put(name, addr);
				functions.add(name);
			}
		}
	}
	
	public static Map<String, Type> getTypes() {
		return types;
	}
	
	public static boolean isLuaFunction(String name) {
		if(name.startsWith(LIBRARY_NAME)) {
			return functions.contains(name.substring(LIBRARY_NAME.length() + 2));
		}
		return functions.contains(name);
	}
	
	public static String getName(Address address) {
		return addr_to_name.get(address.toString());
	}
	
	public static String getNameFromPointer(Address address) {
		Address addr = Util.getAddressPointer(address);
		if(addr == null) return null;
		return addr_to_name.get(addr.toString());
	}
	
	public static boolean isLuaPointer(Address address) {
		Address addr = Util.getAddressPointer(address);
		if(addr == null) return false;
		
		return addr_to_name.containsKey(addr.toString());
	}
	
	
	
	public static void addType(String name, int id) {
		String type_name = name.toLowerCase();
		if(types.containsKey(type_name)) {
			types.get(type_name).id = id;
		} else {
			Type type = new Type(type_name, id);
			types.put(type_name, type);
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
		if(types.containsKey(type_name)) {
			return types.get(type_name);
		}
		
		Type type = new Type(type_name, Integer.MIN_VALUE);
		types.put(type_name, type);
		return type;
	}
	
	public static String getTypeNameFromId(long id) {
		for(Type type : types.values()) {
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
			// This is a little cheat for pretty print.
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
			if(obj == null || !(obj instanceof Type)) return false;
			return name.equals(((Type)obj).name);
		}
		
		@Override
		public String toString() {
			return new StringBuilder().append("(name = '").append(name).append("' id = ").append(Integer.toHexString(id)).append(")").toString();
		}
	}
}
