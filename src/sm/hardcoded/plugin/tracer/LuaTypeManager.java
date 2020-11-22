package sm.hardcoded.plugin.tracer;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import sm.hardcoded.plugin.tracer.ScrapMechanicBookmarkManager.BookmarkCategory;

class LuaTypeManager {
	private final ScrapMechanicPlugin plugin;
	private final ScrapMechanicBookmarkManager manager;
	private Set<Type> types;
	
	LuaTypeManager(ScrapMechanicPlugin tool) {
		types = new HashSet<>();
		plugin = tool;
		manager = tool.getBookmarkManager();
		
		addDefaultTypes();
	}
	
	private void addDefaultTypes() {
		addType("None", -1);
		addType("Nil", 0);
		addType("Boolean", 1);
		addType("Lightuserdata", 2);
		addType("Number", 3);
			addType("Integer", 3);
		addType("String", 4);
		addType("Table", 5);
		addType("Function", 6);
		addType("Userdata", 7);
		addType("Thread", 8);
	}
	
	private void addType(String name, int id) {
		Type type = new Type(name, id);
		if(types.contains(type)) {
			return;
		}
		
		types.add(type);
	}
	
	public void registerTypes(List<SMDefinition> list) {
		plugin.getWindow().writeLog(this, "Registering lua types");
		
		int size = 0;
		for(SMDefinition object : list) {
			String typeAddress = object.getType();
			if(typeAddress == null) continue;
			
			registerType(typeAddress);
			size++;
		}
		
		plugin.getWindow().writeLog(this, "Found " + size + " lua type" + (size == 1 ? "":"s"));
	}
	
	public void registerType(String typeAddress) {
		Program program = plugin.getCurrentProgram();
		if(program == null) return;
		
		AddressFactory factory = program.getAddressFactory();
		
		String name;
		int id;
		
		Bookmark bookmark = manager.getBookmarkFromAddress(typeAddress, BookmarkCategory.LUA_TYPE);
		
		if(bookmark != null) {
			String[] array = bookmark.getComment().split(", ");
			name = array[0];
			id = Integer.valueOf(array[1]);
		} else {
			ProgramMemory memory = plugin.getProgramMemory();
			Address address = factory.getAddress(typeAddress);
			Address nameAddress = memory.readAddress(address);
			
			name = memory.readTerminatedString(nameAddress);
			id = memory.readInt(address.add(4));
			
			manager.addBookmark(address, BookmarkCategory.LUA_TYPE, name + ", " + id);
		}
		
		addType(name, id);
	}
	
	static class Type {
		private String name;
		private int id;
		
		private Type(String print, int id) {
			this.name = print;
			this.id = id;
		}
		
		public String getName() { return name; }
		public int getId() { return id; }
		public int hashCode() { return name.hashCode(); }
		
		public boolean equals(Object obj) {
			if(obj == null || !(obj instanceof Type)) return false;
			return name.equals(((Type)obj).name);
		}
		
		public String toString() {
			return "(name = '" + name + "' id = " + Integer.toHexString(id) + ")";
		}
	}
}
