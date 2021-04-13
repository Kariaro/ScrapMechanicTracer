package com.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import com.hardcoded.plugin.ScrapMechanicPlugin;
import com.hardcoded.plugin.utils.DataUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Reads the full content of a ghidra program and caches it.
 * 
 * @author HardCoded
 * @since 0.1.0
 * @date 2020-11-22
 */
public class ProgramMemory {
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
		long offset = addr.getOffset();
		byte[] bytes = new byte[getAddressSize()];
		
		for(int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte)((offset >> (8L * i)) & 0xff);
		}
		
		/*return findMatches(
			(offset      ) & 0xff,
			(offset >>  8) & 0xff,
			(offset >> 16) & 0xff,
			(offset >> 24) & 0xff
		);*/
		
		return findMatches(bytes);
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
		byte[] bytes = getBytes(addr, getAddressSize());
		
		// TODO: Use the new method?
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < bytes.length; i++) {
			sb.insert(0, String.format("%02x", bytes[i]));
		}
		
		return plugin.getCurrentProgram().getAddressFactory().getAddress(sb.toString());
	}
	
	/**
	 * This was used to read the pointer of a position this is now deprecated because 
	 * the pointer size could change
	 * @param addr
	 * @return
	 */
	public int readInt(Address addr) {
		byte[] bytes = getBytes(addr, 4);
		return DataUtils.getInt(bytes, 0);
		/*
		return (bytes[0] & 0xff) |
			   ((bytes[1] & 0xff) << 8) |
			   ((bytes[2] & 0xff) << 16) |
			   ((bytes[3] & 0xff) << 24);
		*/
	}
	
	// TODO: Make sure this is correct
	public long readWithAddressSize(Address addr) {
		byte[] bytes = getBytes(addr, getAddressSize());
		return DataUtils.getInteger(bytes, getAddressSize(), 0);
		/*
		long result = 0;
		
		for(int i = 0; i < 8; i++) {
			result |= ((bytes[i] & 0xffL) << (8L * i));
		}
		
		return result;
		*/
	}
	
	public byte[] getBytes(Address addr, int size) {
		byte[] result = new byte[size];
		for(int i = 0; i < memory_start.length; i++) {
			Address start = memory_start[i];
			byte[] bytes = memory_bytes[i];
						
			int offset = (int)addr.subtract(start);
			if(offset < 0 || offset >= bytes.length) continue;
			
			System.arraycopy(bytes, offset, result, 0, size);
			
			/*for(int j = 0; j < size; j++) {
				result[j] = bytes[offset + j];
			}*/
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
			
			// StringBuilder sb = new StringBuilder();
			int str_length = 0;
			for(int j = 0; j < length; j++) {
				if(bytes[offset + j] == 0) {
					str_length = j;
					break;
				}
//				byte b = bytes[offset + j];
//				if(b == 0) break;
//				
//				sb.append((char)b);
			}
			
			if(str_length == 0) return "";
			return new String(bytes, offset, str_length);
			// return sb.toString();
		}
		
		return null;
	}
	
	public int getAddressSize() {
		return plugin.getCurrentProgram().getDefaultPointerSize();
	}
}
