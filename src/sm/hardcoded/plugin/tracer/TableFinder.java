package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.program.database.bookmark.BookmarkDBManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

public class TableFinder {
	private static final String NAME_PATTERN = "([a-zA-Z0-9.])+";
	
	private final ScrapMechanicPlugin plugin;
	TableFinder(ScrapMechanicPlugin tool) {
		plugin = tool;
	}
	
	// TODO: Clear these to save ram
	private Address[] memory_start;
	private byte[][] memory_bytes;
	
	public void loadMemory() throws MemoryAccessException {
		Program program = plugin.getCurrentProgram();
		if(program == null) return;
		
		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();
		
		List<Address> starts = new ArrayList<>();
		List<byte[]> list = new ArrayList<>();
		for(MemoryBlock block : blocks) {
			if(!block.isInitialized()) continue;
			
			int length = (int)block.getEnd().subtract(block.getStart());
			byte[] bytes = new byte[length];
			
			block.getBytes(block.getStart(), bytes);
			list.add(bytes);
			starts.add(block.getStart());
		}
		
		memory_bytes = list.toArray(byte[][]::new);
		memory_start = starts.toArray(Address[]::new);
	}
	
	public List<FunctionPointer> findFunctionTable() {
		Program program = plugin.getCurrentProgram();
		if(program == null) return null;
		
		// Creating A GhidraPlugin for Lua C Functions?
		Iterator<Bookmark> iterator = program.getBookmarkManager().getBookmarksIterator("ScrapMechanicTracerAnalysis");
		
		List<StringPointer> stringPointers = new ArrayList<>();
		for(Address addr : findMatches(0, 0x73, 0x6D, 0x2E)) { // '\0sm.'
			addr = addr.add(1);
			
			String str = readTerminatedString(addr);
			
			if(str.matches(NAME_PATTERN)) {
				stringPointers.add(new StringPointer(addr, str));
			}
		}
		
		List<FunctionPointer> tables = new ArrayList<>();
		
		long time = System.currentTimeMillis();
		// pointers will contain "probably" the correct string addresses.
		for(StringPointer string : stringPointers) {
			// StructurePointers
			List<Address> matches = findMatches(string.addr);
			
			boolean found = false;
			for(Address address : matches) {
				Address ptr = readAddress(address.add(4));
				if(!isValidAddress(ptr)) continue;
				
				byte[] info = getBytes(ptr.subtract(1), 2);
				
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
			}
		}
		
		
		Msg.debug(this, "----------------------------------------");
		Msg.debug(this, "Took: " + (System.currentTimeMillis() - time) + " ms");
		Msg.debug(this, "----------------------------------------");
		
		return tables;
	}
	
	private List<Address> findMatches(Address addr) {
		int offset = (int)addr.getOffset();
		return findMatches(
			(offset      ) & 0xff,
			(offset >>  8) & 0xff,
			(offset >> 16) & 0xff,
			(offset >> 24) & 0xff
		);
	}
	
	private List<Address> findMatches(int... pattern) {
		byte[] array = new byte[pattern.length];
		for(int i = 0; i < pattern.length; i++) array[i] = (byte)(pattern[i] & 0xff);
		return findMatches(array);
	}
	
	private List<Address> findMatches(byte... pattern) {
		List<Address> list = new ArrayList<>();
		
		for(int i = 0; i < memory_start.length; i++) {
			Address start = memory_start[i];
			byte[] bytes = memory_bytes[i];
			
			for(int j = 0; j < bytes.length - pattern.length; j++) {
				for(int k = 0; k < pattern.length; k++) {
					if(bytes[j + k] != pattern[k]) break;
					
					if(k == pattern.length - 1) {
						list.add(start.add(j));
					}
				}
			}
		}
		
		return list;
	}
	
	private Address readAddress(Address addr) {
		byte[] bytes = getBytes(addr, 4);
		return plugin.getCurrentProgram().getAddressFactory().getAddress(
			String.format("%02x%02x%02x%02x", bytes[3], bytes[2], bytes[1], bytes[0])
		);
	}
	
	private byte[] getBytes(Address addr, int size) {
		byte[] result = new byte[size];
		for(int i = 0; i < memory_start.length; i++) {
			Address start = memory_start[i];
			byte[] bytes = memory_bytes[i];
						
			int offset = (int)addr.subtract(start);
			if(offset < 0 || offset >= bytes.length) continue;
			
			for(int j = 0; j < size; j++) {
				result[j] = bytes[offset + j];
			}
		}
		
		return result;
	}
	
	private boolean isValidAddress(Address addr) {
		for(int i = 0; i < memory_start.length; i++) {
			Address start = memory_start[i];
			byte[] bytes = memory_bytes[i];
						
			int offset = (int)addr.subtract(start);
			if(offset < 0 || offset >= bytes.length) continue;
			
			return true;
		}
		
		return false;
	}
	
	// NOTE - If a string overlaps multiple memoryblocks than this might be a problem :&
	private String readTerminatedString(Address addr) { return readTerminatedString(addr, 256); }
	private String readTerminatedString(Address addr, int maxLength) {
		for(int i = 0; i < memory_start.length; i++) {
			Address start = memory_start[i];
			byte[] bytes = memory_bytes[i];
						
			int offset = (int)addr.subtract(start);
			if(offset < 0 || offset >= bytes.length) continue;
			
			int length = maxLength;
			if(length + offset >= bytes.length) {
				length = bytes.length - offset;
			}
			
			StringBuilder sb = new StringBuilder();
			for(int j = 0; j < length; j++) {
				byte b = bytes[offset + j];
				if(b == 0) break;
				
				sb.append((char)b);
			}
			
			return sb.toString();
		}
		
		return null;
	}
}
