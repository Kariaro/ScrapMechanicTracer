package sm.util;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;

public class Util {
	private static GhidraScript SCRIPT;
	public static void init(GhidraScript ghidra) {
		Util.SCRIPT = ghidra;
	}
	
	public static GhidraScript getScript() {
		return SCRIPT;
	}
	
	public static TaskMonitor getMonitor() {
		return SCRIPT.getMonitor();
	}
	
	public static boolean isMonitorCancelled() {
		return SCRIPT.getMonitor().isCancelled();
	}
	
	public static Program getProgram() {
		return SCRIPT.getCurrentProgram();
	}
	
	public static DataTypeManager getDataTypeManager() {
		return getProgram().getDataTypeManager();
	}
	
	
	public static boolean isValidAddress(Address addr) {
		return SCRIPT.getAddressFactory().isValidAddress(addr);
	}
	
	public static String readTerminatedString(Address addr) {
		return readTerminatedString(addr, 256);
	}
	
	public static String readTerminatedString(Address addr, int max_length) {
		if(!addr.isMemoryAddress()) return null;
		if(addr.getOffset() == 0) return null;
		
		ByteArrayOutputStream bs = new ByteArrayOutputStream();
		try {
			for(int i = 0; i < max_length; i++) {
				byte read = SCRIPT.getByte(addr);
				
				if(read == 0) {
					return new String(bs.toByteArray());
				}
				
				bs.write(read);
				addr = addr.add(1);
			}
		} catch(Exception e) {
			// TODO: Print something here!
			
			e.printStackTrace();
		}
		
		if(bs.size() == 0) {
			return null;
		}
		
		return new String(bs.toByteArray());
	}

	public static int getFunctionLength(Function func) {
		AddressSetView view = func.getBody();
		Address min = view.getMinAddress();
		Address max = view.getMaxAddress();
		return (int)(max.getOffset() - min.getOffset());
	}
	
	public static Address[] findBytesInFunction(Function func, String bytePattern) {
		return findBytesInFunction(func, bytePattern, 8);
	}
	public static Address[] findBytesInFunction(Function func, String bytePattern, int max_finds) {
		if(max_finds < 1) return null;
		
		// Parse pattern
		int[] pattern;
		{
			int[] prepts = new int[256];
			int idx = 0;
			for(int i = 0; i < bytePattern.length(); i++) {
				String sub = bytePattern.substring(i);
				if(sub.startsWith("\\x")) {
					prepts[idx++] = Integer.parseInt(sub.substring(2, 4), 16);
					i += 3;
					continue;
				}
				prepts[idx++] = -1;
			}
			
			pattern = new int[idx];
			System.arraycopy(prepts, 0, pattern, 0, idx);
		}
		
		byte[] bytes;
		try {
			bytes = SCRIPT.getBytes(func.getEntryPoint(), getFunctionLength(func));
		} catch(MemoryAccessException e) {
			e.printStackTrace();
			return null;
		}
		
		Address entry = func.getEntryPoint();
		List<Address> list = new ArrayList<>();
		for(int i = 0; i < bytes.length - pattern.length; i++) {
			if(_fitsPattern(bytes, pattern, i)) {
				list.add(entry.add(i));
				if(list.size() >= max_finds) return list.toArray(Address[]::new);
			}
		}
		
		return list.toArray(Address[]::new);
	}
	
	private static boolean _fitsPattern(byte[] bytes, int[] pattern, int offset) {
		for(int i = 0; i < pattern.length; i++) {
			int val = Byte.toUnsignedInt(bytes[i + offset]);
			int chk = pattern[i];
			
			if(chk < 0) continue;
			if(val != chk) return false;
		}
		
		return true;
	}
	
	public static Function getFunctionAt(Address addr) {
		Function result = SCRIPT.getFunctionAt(addr);
		if(result == null) {
			result = SCRIPT.createFunction(addr, "FUN_" + addr);
			return result;
		}
		
		return result;
	}
	
	public static Function getFunctionAt(Address addr, boolean createNew, String name) {
		Function result = SCRIPT.getFunctionAt(addr);
		if(result == null && createNew) {
			result = SCRIPT.createFunction(addr, name);
			return result;
		}
		
		return result;
	}
	
	public static Function getFunctionAt(String func) {
		AddressFactory addressFactory = SCRIPT.getAddressFactory();
		Address addr = addressFactory.getAddress(func);
		return getFunctionAt(addr);
	}
	
	public static Instruction getInstructionAt(Address address) {
		return SCRIPT.getInstructionAt(address);
	}
	
	public static Instruction getInstructionAt(HighFunction function) {
		return SCRIPT.getInstructionAt(function.getFunction().getEntryPoint());
	}
	
	public static Instruction getInstructionBefore(Address address) {
		return SCRIPT.getInstructionBefore(address);
	}
	
	public static Instruction getInstructionBefore(HighFunction function) {
		return SCRIPT.getInstructionBefore(function.getFunction().getEntryPoint());
	}

	public static long getOffset(Function func, Address addr) {
		return addr.getOffset() - func.getEntryPoint().getOffset();
	}
	
	public static boolean isInside(Instruction inst, Function func) {
		Address max_addr = func.getBody().getMaxAddress();
		Address cur_addr = inst.getAddress();
		
		return max_addr.compareTo(cur_addr) >= 0;
	}
	
	public static boolean isInside(Instruction inst, HighFunction func) {
		Address max_addr = func.getFunction().getBody().getMaxAddress();
		Address cur_addr = inst.getAddress();
		
		return max_addr.compareTo(cur_addr) >= 0;
	}
	
	public static Address getAddressPointer(Address addr) {
		if(!addr.isMemoryAddress()) return null;
		try {
			return SCRIPT.getAddressFactory().getAddress(Integer.toHexString(SCRIPT.getInt(addr)));
		} catch(MemoryAccessException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static int toSignedInt(Object obj) {
		if(obj instanceof Number) {
			return ((Number)obj).intValue();
		}
		return 0;
	}
	
	public static Varnode getPcodeVarnode(Varnode[] nodes, int... arr) {
		if(arr.length < 1 || arr[0] >= nodes.length) return null;
		Varnode node = nodes[arr[0]];
		if(node == null) return null;
		
		for(int i = 1; i < arr.length; i++) {
			PcodeOp op = node.getDef();
			if(op == null) return null;
			if(arr[i] >= op.getNumInputs()) return null;
			
			node = op.getInput(arr[i]);
		}
		return node;
	}
	
	public static Varnode getPcodeVarnode(PcodeOpAST command, int... arr) {
		if(arr.length < 1 || arr[0] >= command.getNumInputs()) return null;
		Varnode node = command.getInput(arr[0]);
		if(node == null) return null;
		
		for(int i = 1; i < arr.length; i++) {
			node = node.getDef().getInput(arr[i]);
		}
		return node;
	}

	public static Address getAddress(String addr) {
		if(addr == null) return null;
		return SCRIPT.getAddressFactory().getAddress(addr);
	}
	
	public static Address getAddressFromPointer(Address addr) throws MemoryAccessException {
		return getAddressFromInt(SCRIPT.getInt(addr));
	}
	
	public static int readInt(Address address, boolean bigEndian) throws MemoryAccessException {
		int value = SCRIPT.getInt(address);
		if(bigEndian) {
			return value;
		} else {
			int a = (value >>> 24) & 0xff;
			int b = (value >>> 16) & 0xff;
			int c = (value >>>  8) & 0xff;
			int d = (value       ) & 0xff;
			return (d << 24) | (c << 16) | (b << 8) | a;
		}
	}
	
	public static Address getAddressFromLong(long offset) {
		return getAddress(Long.toHexString(offset));
	}
	
	public static Address getAddressFromInt(int offset) {
		return getAddress(Integer.toHexString(offset));
	}
	
	
	/**
	 * This method reads all bytes from a function and hashes it.
	 * This is used when caching functions to faster decompile sources.
	 * 
	 * @param func
	 * @return
	 */
	@Deprecated public static String getFunctionHash(Function func) {
		throw new UnsupportedOperationException("Implement this function!");
	}
}
