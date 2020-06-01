package sm.util;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import sm.SMObject;

public class SMUtil {
	private static final String PUSH = "PUSH";
	private static final String CALL = "CALL";
	
	/* TODO: Check if this method has any errors
	 */
	public static SMObject loadSMObject(LuaReg ref) throws MemoryAccessException {
		Function func = ref.getFunction();
		SMObject object = new SMObject(ref.getBase(), func);
		
		//System.out.println("Printing Function: " + func);
		Instruction iter = Util.getScript().getInstructionAt(func.getEntryPoint()).getPrevious();
		List<Instruction> list = new ArrayList<>();
		
		int length = Util.getFunctionLength(func);
		Address push_find = null;
		
		
		do {
			iter = iter.getNext();
			Address addr = iter.getAddress();
			if(Util.getOffset(func, addr) > length) break;
			
			String mnemonic = iter.getMnemonicString();
			if(PUSH.equals(mnemonic)) {
				list.add(iter);
				
				if(push_find != null) {
					Address check = iter.getAddress(0);
					
					if(push_find.equals(check)) {
						//System.out.println("    : Constant address -> " + list.get(0).getAddress(0));
						object.importConstant(list.get(0).getAddress(0));
					}
				}
			} else {
				if(CALL.equals(mnemonic)) {
					if(list.size() == 3) {
						Address addr_0 = list.get(0).getAddress(0);
						Address addr_1 = list.get(1).getAddress(0);
						Address addr_2 = list.get(2).getAddress(0);
						
						if(addr_2 == null) {
							//System.out.printf("    : luaL_register( lua_State, table = %s, name = %s )\n", addr_0, addr_1);
							object.importRegister(addr_1, addr_0);
							
							// Check for addr_1 in push after this point to get InitializeSmVariable
							push_find = addr_1;
						} else {
							//System.out.printf("    : CreateUserdata( lua_State, table = %s, userdata = %s, type = %s )\n", addr_0, addr_1, addr_2);
							object.importUserdata(addr_0, addr_1, addr_2);
							
							LuaUtil.addType(addr_2);
						}
					}
				}
				
				list.clear();
			}
		} while(iter != null);
		list.clear();
		
		return object;
	}
}
