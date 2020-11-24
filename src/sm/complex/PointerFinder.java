package sm.complex;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import sm.util.SMUtil;
import sm.util.Util;

/**
 * This class will search trough the '.RDATA' part of the
 * memory and search for all strings that starts with '\0sm.'
 * and that matches the pattern '[a-zA-Z0-9.]+'.
 * 
 * @author HardCoded
 */
@Deprecated(forRemoval = true)
public final class PointerFinder {
	// TODO: Custom memory block searching
	private static final String NAME_PATTERN = "[a-zA-Z0-9.]+";
	private static final int MAX_STRUCTURE_SIZE = 256;
	
	private static Set<Address> structures;
	private static String version;
	
	public static void init(GhidraScript ghidra) throws Exception {
		version = findVersionString(
			ScrapMechanic.STRINGS_MEMORY_BLOCK,
			ScrapMechanic.STRINGS_MEMORY_BLOCK
		);
		
		List<StringPointer> list = new ArrayList<>();
		findStrings(ScrapMechanic.STRINGS_MEMORY_BLOCK, list);
		
		List<StringPointer> groupList = new ArrayList<>();
		findReferences(ScrapMechanic.REFERENCES_MEMORY_BLOCK, list, groupList);
		
		structures = new HashSet<>();
		findStructures(groupList, list, structures);
		
		System.out.println("Structures:");
		for(Address structure : structures) {
			System.out.println("  pointer = " + structure);
		}
		
		System.out.println();
		System.out.println("Version: " + version);
		System.out.println();
	}
	
	public static Set<Address> getStructures() {
		return structures;
	}
	
	public static String getVersion() {
		return version;
	}
	
	private static String findVersionString(String stringBlock, String referenceBlock) throws Exception {
		Address matchAddress = null;
		{
			MemoryBlock block = getMemoryBlock(stringBlock);
			if(block == null) {
				System.out.println("Failed to find memoryBlock '" + stringBlock + "'");
				return null;
			}
			
			Address blockStart = block.getStart();
			int size = (int)block.getEnd().subtract(blockStart);
			
			byte[] blockBytes = new byte[size];
			block.getBytes(blockStart, blockBytes);
	
			// Get all addresses to strings that start with '\0version\0'
			List<Address> matches = new ArrayList<>();
			findMatchingAddresses(blockBytes, "\0version\0", 1 + (int)blockStart.getOffset(), matches);
			
			if(matches.isEmpty()) {
				System.out.println("Failed to find the string '\\0version\\0' in memory");
				return null;
			}
			
			matchAddress = matches.get(0);
		}
		
		{
			MemoryBlock block = getMemoryBlock(referenceBlock);
			if(block == null) {
				System.out.println("Failed to find memoryBlock '" + referenceBlock + "'");
				return null;
			}
			
			Address blockStart = block.getStart();
			int size = (int)block.getEnd().subtract(blockStart);
			
			byte[] blockBytes = new byte[size];
			block.getBytes(blockStart, blockBytes);
			
			List<Address> matches = new ArrayList<>();
			findMatchingAddresses(blockBytes, getPattern(matchAddress), (int)blockStart.getOffset(), matches);
			
			//System.out.println("Version pointer: " + matchAddress);
			//System.out.println("Version paths: " + matches);
			
			
			//System.out.println("Version result: " + result);
			return SMUtil.loadVersionString(Util.getAddressFromPointer(matches.get(0).add(4)));
		}
	}
	
	private static void findStrings(String blockName, List<StringPointer> list) throws Exception {
		MemoryBlock block = getMemoryBlock(blockName);
		if(block == null) {
			System.out.println("Failed to find memoryBlock '" + blockName + "'");
			return;
		}
		
		Address blockStart = block.getStart();
		int size = (int)block.getEnd().subtract(blockStart);
		
		byte[] blockBytes = new byte[size];
		block.getBytes(blockStart, blockBytes);
		
		
		// Get all addresses to strings that start with '\0sm.'
		List<Address> matches = new ArrayList<>();
		findMatchingAddresses(blockBytes, "\0sm.", 1 + (int)blockStart.getOffset(), matches);
		
		// Filter out any strings that does not match the NAME_PATTERN
		for(int i = 0; i < matches.size(); i++) {
			Address addr = matches.get(i);
			String name = getString(blockBytes, blockStart, addr);
			
			if(name.matches(NAME_PATTERN)) {
				list.add(new StringPointer(addr, name));
			} else {
				matches.remove(i--);
			}
		}
	}
	
	private static void findReferences(String blockName, List<StringPointer> pointers, List<StringPointer> groupList) throws Exception {
		MemoryBlock block = getMemoryBlock(blockName);
		if(block == null) {
			System.out.println("Failed to find memoryBlock '" + blockName + "'");
			return;
		}
		
		Address blockStart = block.getStart();
		int size = (int)block.getEnd().subtract(blockStart);
		
		byte[] blockBytes = new byte[size];
		block.getBytes(blockStart, blockBytes);
		
		for(int i = 0; i < pointers.size(); i++) {
			StringPointer pointer = pointers.get(i);

			List<Address> matches = new ArrayList<>();
			findMatchingAddresses(blockBytes, getPattern(pointer.addr), (int)blockStart.getOffset(), matches);
			
			if(matches.size() == 1) {
				// Exact match
				
				groupList.add(new StringPointer(matches.get(0), pointer.name));
			} else {
				// Not an exact match: Grrrr.
				
				// TODO: Complex algorithm to find the pointers!
				System.out.println("name = " + pointer.name);
				System.out.println("addr = " + pointer.addr);
				System.out.println("    list = " + matches);
			}
		}
	}
	
	private static void findStructures(List<StringPointer> elements, List<StringPointer> names, Set<Address> set) {
		for(StringPointer pointer : elements) {
			Address addr = pointer.addr;
			
			try {
				int max = MAX_STRUCTURE_SIZE;
				while(max-- > 0) {
					addr = addr.subtract(8);
					Address check = Util.getAddressFromPointer(addr);
					
					if(!contains(check, names)) {
						set.add(addr.add(8));
						break;
					}
				}
			} catch(Throwable e) {
				// MemoryOutOfBounds???
				e.printStackTrace();
			}
		}
	}
	
	private static boolean contains(Address pointer, List<StringPointer> pointers) {
		for(StringPointer ptr : pointers) {
			if(ptr.addr.getOffset() == pointer.getOffset()) return true;
		}
		return false;
	}
	
	private static void findMatchingAddresses(byte[] bytes, String find, int offset, List<Address> list) {
		findMatchingAddresses(bytes, find.getBytes(), offset, list);
	}
	private static void findMatchingAddresses(byte[] bytes, byte[] pattern, int offset, List<Address> list) {
		for(int i = 0; i < bytes.length - pattern.length; i++) {
			for(int j = 0; j < pattern.length; j++) {
				if(bytes[i + j] != pattern[j]) break;
				
				if(j == pattern.length - 1) {
					list.add(Util.getAddressFromInt(i + offset));
				}
			}
		}
	}
	
	private static String getString(byte[] data, Address start, Address addr) {
		return getString(data, start, addr, 256);
	}
	private static String getString(byte[] data, Address start, Address addr, int max) {
		StringBuilder sb = new StringBuilder();
		int offset = (int)addr.subtract(start);
		
		for(int i = offset; i < data.length; i++) {
			byte b = data[i];
			
			if(b == 0 || max-- <= 0) break;
			sb.append((char)b);
		}
		return sb.toString();
	}
	
	private static MemoryBlock getMemoryBlock(String blockName) {
		Memory memory = Util.getProgram().getMemory();
		
		MemoryBlock[] blocks = memory.getBlocks();
		for(MemoryBlock block : blocks) {
			if(!block.isInitialized()) continue;
			String name = block.getName();
			
			if(name.equals(blockName)) {
				return block;
			}
		}
		
		return null;
	}
	
	private static byte[] getPattern(Address address) {
		long offset = address.getOffset();
		
		return new byte[] {
			(byte)((offset >>  0) & 0xff),
			(byte)((offset >>  8) & 0xff),
			(byte)((offset >> 16) & 0xff),
			(byte)((offset >> 24) & 0xff),
		};
	}
	
	static class StringPointer {
		Address addr;
		String name;
		
		public StringPointer(Address addr, String name) {
			this.addr = addr;
			this.name = name;
		}
	}
}