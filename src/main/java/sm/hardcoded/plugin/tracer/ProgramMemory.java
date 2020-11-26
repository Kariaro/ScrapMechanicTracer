package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Reads the full content of a ghidra program and caches it.
 * 
 * @date 2020-11-22
 * @author HardCoded
 */
class ProgramMemory {
	private final ScrapMechanicPlugin plugin;
	
	private Address[] memory_start;
	private byte[][] memory_bytes;
	
	public ProgramMemory(ScrapMechanicPlugin tool) {
		plugin = tool;
	}
	
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
	
	public List<Address> findMatches(Address addr) {
		int offset = (int)addr.getOffset();
		return findMatches(
			(offset      ) & 0xff,
			(offset >>  8) & 0xff,
			(offset >> 16) & 0xff,
			(offset >> 24) & 0xff
		);
	}
	
	public List<Address> findMatches(int... pattern) {
		byte[] array = new byte[pattern.length];
		for(int i = 0; i < pattern.length; i++) array[i] = (byte)(pattern[i] & 0xff);
		return findMatches(array);
	}
	
	public List<Address> findMatches(byte... pattern) {
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
	
	public Address readAddress(Address addr) {
		byte[] bytes = getBytes(addr, 4);
		return plugin.getCurrentProgram().getAddressFactory().getAddress(
			String.format("%02x%02x%02x%02x", bytes[3], bytes[2], bytes[1], bytes[0])
		);
	}
	
	public int readInt(Address addr) {
		byte[] bytes = getBytes(addr, 4);
		
		return (bytes[0] & 0xff) |
			   ((bytes[1] & 0xff) << 8) |
			   ((bytes[2] & 0xff) << 16) |
			   ((bytes[3] & 0xff) << 24);
	}
	
	public byte[] getBytes(Address addr, int size) {
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
	
	public boolean isValidAddress(Address addr) {
		for(int i = 0; i < memory_start.length; i++) {
			Address start = memory_start[i];
			byte[] bytes = memory_bytes[i];
						
			int offset = (int)addr.subtract(start);
			if(offset < 0 || offset >= bytes.length) continue;
			
			return true;
		}
		
		return false;
	}
	
	// note: If a string overlaps multiple memoryblocks than this might be a problem :&
	public String readTerminatedString(Address addr) { return readTerminatedString(addr, 256); }
	public String readTerminatedString(Address addr, int maxLength) {
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
