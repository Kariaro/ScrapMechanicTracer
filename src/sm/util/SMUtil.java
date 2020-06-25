package sm.util;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import sm.SMObject;

// https://htmlpreview.github.io/?https://github.com/dragonGR/Ghidra/blob/master/Ghidra/Features/Base/src/main/help/help/topics/AutoAnalysisPlugin/AutoAnalysis.htm
public class SMUtil {
	private static final String PUSH = "PUSH";
	private static final String CALL = "CALL";
	
	public static SMObject loadSMObject(LuaReg reg) throws MemoryAccessException, Exception {
		Address entry = Util.getAddress(reg.func);
		
		Function func = FunctionUtil.createFunction(entry);
		Instruction iter = Util.getInstructionAt(entry);
		
		if(iter == null) {
			// TODO: What do we do now. We could not read the instruction. What next?
			throw new Exception("Could not read the instruction at address ' " + entry + " '");
		}
		
		SMObject object = new SMObject(reg.getBase(), func);
		List<Instruction> list = new ArrayList<>();
		
		Address push_find = null;
		while((iter = iter.getNext()) != null) {
			Address addr = iter.getAddress();
			
			// TODO: Is this safe to assume?
			//if(Util.getOffset(func, addr) > length) break;
			if(!func.getBody().contains(addr)) break;
			
			String mnemonic = iter.getMnemonicString();
			if(PUSH.equals(mnemonic)) {
				list.add(iter);
				
				if(push_find != null) {
					Address check = getAddress(iter);
					
					if(push_find.equals(check)) {
						// System.out.println("    : Constant address -> " + list.get(0).getAddress(0));
						object.importConstant(getAddress(list.get(0)));
					}
				}
			} else {
				if(CALL.equals(mnemonic)) {
					if(list.size() == 3) {
						Address addr_0 = getAddress(list.get(0));
						Address addr_1 = getAddress(list.get(1));
						Address addr_2 = getAddress(list.get(2));
						
						if(addr_2 == null) {
							// System.out.printf("    : luaL_register( lua_State, table = %s, name = %s )\n", addr_0, addr_1);
							object.importRegister(addr_1, addr_0);
							
							push_find = addr_1;
						} else {
							// System.out.printf("    : CreateUserdata( lua_State, table = %s, userdata = %s, type = %s )\n", addr_0, addr_1, addr_2);
							object.importUserdata(addr_0, addr_1, addr_2);
							
							LuaUtil.addType(addr_2);
						}
					}
				}
				
				list.clear();
			}
		}
		
		list.clear();
		
		System.out.println(object);
		
		return object;
	}
	
	public static String loadVersionString(Address entry) throws MemoryAccessException, Exception {
		Function func = FunctionUtil.createFunction(entry);
		Instruction iter = Util.getInstructionAt(entry);
		
		List<Instruction> list = new ArrayList<>();
		
		String version = null;
		String buildVersion = null;
		
		boolean skipNext = false;
		while((iter = iter.getNext()) != null) {
			Address addr = iter.getAddress();
			
			//if(Util.getOffset(func, addr) > length) break;
			if(!func.getBody().contains(addr)) break;
			
			String mnemonic = iter.getMnemonicString();
			
			if(Byte.toUnsignedInt(iter.getByte(0)) == 0xba && buildVersion == null) {
				buildVersion = Integer.toString(iter.getInt(1));
				// System.out.println("BuildVersion: " + buildVersion);
				skipNext = true;
			}
			
			if(PUSH.equals(mnemonic)) {
				list.add(iter);
			} else {
				if(CALL.equals(mnemonic)) {
					if(skipNext) {
						skipNext = false;
						list.clear();
						continue;
					}
					
					// System.out.println(addr + ", " + iter);
					
					for(Instruction inst : list) {
						Address address = getAddress(inst);
						
						if(Util.isValidAddress(address)) {
							// System.out.println("    addr = " + address);
							version = Util.readTerminatedString(address);
							break;
						}
					}
					
					// System.out.println("List: " + list);
					list.clear();
					break;
				}
				
			}
		}
		list.clear();
		
		return version + '.' + buildVersion;
	}
	
	private static Address getAddress(Instruction inst) {
		String string = inst.toString();
		String sub = string.substring(string.indexOf("0x") + 2);
		return Util.getAddress(sub);
	}
}
