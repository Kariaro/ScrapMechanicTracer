package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import sm.hardcoded.plugin.tracer.ScrapMechanicBookmarkManager.BookmarkCategory;

class TableFinder {
	private static final String NAME_PATTERN = "([a-zA-Z0-9.])+";
	
	private final ScrapMechanicPlugin plugin;
	private final ScrapMechanicBookmarkManager manager;
	
	TableFinder(ScrapMechanicPlugin tool) {
		plugin = tool;
		manager = tool.getBookmarkManager();
	}
	
	public List<FunctionPointer> findFunctionTable() {
		Program program = plugin.getCurrentProgram();
		if(program == null) return null;
		
		long time = System.currentTimeMillis();
		
		ProgramMemory memory = plugin.getProgramMemory();
		
		List<StringPointer> stringPointers = new ArrayList<>();
		{
			plugin.getWindow().writeLog(this, "Finding string pointers");
			
			int size = 0;
			List<Bookmark> bookmarks = manager.getBookmarks(BookmarkCategory.STRING_POINTER);
			for(Address addr : memory.findMatches(0, 0x73, 0x6D, 0x2E)) { // '\0sm.'
				addr = addr.add(1);
				
				String str = memory.readTerminatedString(addr);
				boolean hasBookmark = false;
				for(Bookmark bookmark : bookmarks) {
					if(bookmark.getComment().equals(str)) {
						stringPointers.add(new StringPointer(bookmark.getAddress(), bookmark.getComment()));
						hasBookmark = true;
						break;
					}
				}
				
				if(hasBookmark) continue;
				if(str.matches(NAME_PATTERN)) {
					stringPointers.add(new StringPointer(addr, str));
					manager.addBookmark(addr, BookmarkCategory.STRING_POINTER, str);
					
					size ++;
				}
			}
			
			
			int cached = stringPointers.size() - size;
			plugin.getWindow().writeLog(this, cached + " pointer" + (cached == 1 ? "":"s") + " read from cache");
			plugin.getWindow().writeLog(this, size + " pointer" + (size == 1 ? "":"s") + " read from memory");
		}
		
		List<FunctionPointer> tables = new ArrayList<>();
		{
			List<Bookmark> bookmarks = manager.getBookmarks(BookmarkCategory.DEFINING_FUNCTION);
			
			// pointers will contain "probably" the correct string addresses.
			if(!bookmarks.isEmpty()) {
				plugin.getWindow().writeLog(this, "Reading function pointers from cache");
				
				AddressFactory factory = program.getAddressFactory();
				
				for(Bookmark bookmark : bookmarks) {
					String[] ptrs = bookmark.getComment().split(", ");
					if(ptrs.length != 2) continue;
					
					for(int i = 0; i < stringPointers.size(); i++) {
						StringPointer string = stringPointers.get(i);
						
						if(string.addr.toString().equals(ptrs[0])) {
							Address ptr = bookmark.getAddress();
							Address address = factory.getAddress(ptrs[1]);
							
							tables.add(new FunctionPointer(string, ptr, address));
							stringPointers.remove(i);
							break;
						}
					}
				}
				
				if(stringPointers.size() > 0) {
					plugin.getWindow().writeLog(this, "Failed to find some function pointers. Reading default");
				}
			} else {
				plugin.getWindow().writeLog(this, "Finding function pointers");
			}
			
			plugin.getWindow().setProgressBar(0);
			
			int pointerIndex = 0;
			for(StringPointer string : stringPointers) {
				List<Address> matches = memory.findMatches(string.addr);
				
				boolean found = false;
				for(Address address : matches) {
					Address ptr = memory.readAddress(address.add(4));
					if(!memory.isValidAddress(ptr)) continue;
					
					byte[] info = memory.getBytes(ptr.subtract(1), 2);
					
					// If the pointer address has 0 infront of it.
					// then it's probably not inside a function
					if(info[0] == 0) continue;
					if(info[1] != 0x55) continue; // PUSH EBP
					
					if(found) {
						// TODO: Remove the other same pointer because it might be wrong.
						
						Msg.error(this, "Found multiple pointers for ('" + string.str + "') [" + address + "] [" + ptr + "]");
						tables.get(tables.size() - 1);
						break;
					}
					
					found = true;
	
					// TODO: There could still be multiple found pointers.
					// The pointer to these strings will always be loaded with either..
					
					// LEA, MOV, PUSH
					// 68 /* PUSH */, string_address
					
					// Msg.debug(this, "Pointer for ('" + string.str + "') [" + address + "] [" + ptr + "]");
					
					tables.add(new FunctionPointer(string, ptr, address));
					manager.addBookmark(ptr, BookmarkCategory.DEFINING_FUNCTION, string.addr + ", " + address);
					
					int size = stringPointers.size();
					plugin.getWindow().setProgressBar((++pointerIndex) / (size + 0.0), size);
				}
			}
			
			plugin.getWindow().setProgressBar(1);
		}
		
		plugin.getWindow().writeLog(this, "Took " + (System.currentTimeMillis() - time) + " ms");
		
		return tables;
	}
}
