package com.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import com.hardcoded.plugin.ScrapMechanicPlugin;
import com.hardcoded.plugin.tracer.ScrapMechanicBookmarkManager.BookmarkCategory;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;

class LuaTypeManager {
	private final ScrapMechanicPlugin plugin;
	private final ScrapMechanicBookmarkManager manager;
	private List<Type> types;
	
	LuaTypeManager(ScrapMechanicPlugin tool) {
		types = new ArrayList<>();
		plugin = tool;
		manager = tool.getBookmarkManager();
		
		addDefaultTypes();
	}
	
	private void addDefaultTypes() {
		addType("none", -1);
		addType("nil", 0);
		addType("boolean", 1);
		addType("lightuserdata", 2);
		addType("number", 3);
			addType("integer", 3);
		addType("string", 4);
		addType("table", 5);
		addType("function", 6);
		addType("userdata", 7);
		addType("thread", 8);
	}
	
	private void addType(String name, int id) {
		Type type = new Type(name, id);
		if(types.contains(type)) return;
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
			//id = memory.readInt(address.add(memory.getAddressSize()));
			id = memory.readInt(address.add(memory.getAddressSize()));
			
			manager.addBookmark(address, BookmarkCategory.LUA_TYPE, name + ", " + id);
		}
		
		addType(name, id);
	}
	
	public Type getType(int id) {
		for(Type type : types) {
			if(type.id == id) return type;
		}
		
		return null;
	}
	
	static class Type {
		private final String name;
		private final int id;
		
		private Type(String print, int id) {
			this.name = print;
			this.id = id;
		}
		
		public String getName() { return name; }
		public int getId() { return id; }
		
		public int hashCode() {
			return name.hashCode();
		}
		
		public boolean equals(Object obj) {
			if(!(obj instanceof Type)) return false;
			return obj.hashCode() == hashCode();
		}
		
		public String toString() {
			return "(name = '" + name + "' id = " + Integer.toHexString(id) + ")";
		}
	}
}
