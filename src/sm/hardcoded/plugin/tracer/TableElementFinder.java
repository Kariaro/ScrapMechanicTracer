package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import sm.SMObject;

class TableElementFinder {
	private final ScrapMechanicPlugin plugin;
	
	TableElementFinder(ScrapMechanicPlugin tool) {
		plugin = tool;
		
	}

	public SMObject findSMObject(FunctionPointer func) {
		Program program = plugin.getCurrentProgram();
		
		// The program should not have been analyzed here so there is no worry that we do stuff that we do not need to do.
		// DissasemblerPlugin:216 - StaticDissasemble.
		
		DisassembleCommand cmd = new DisassembleCommand(func.entry, null, true);
		cmd.enableCodeAnalysis(false);
		if(!cmd.applyTo(program)) {
			Msg.warn(this, "Failed to disassemble memory at address '" + func.entry + "'");
		}
		
		Instruction iter = program.getListing().getInstructionAt(func.entry);
		
		SMObject object = new SMObject(func.location, func.entry);
		List<Instruction> list = new ArrayList<>();
		
		Address push_find = null;
		do {
			iter = iter.getNext();
			
			String mnemonic = iter.getMnemonicString();
			switch(mnemonic) {
				case "RET": {
					iter = null;
					continue;
				}
				
				case "PUSH": {
					list.add(iter);
					
					if(push_find != null) {
						Address check = getAddress(iter, 0);
						
						if(push_find.equals(check)) {
							// System.out.println("    : Constant address -> " + list.get(0).getAddress(0));
							object.importConstant(getAddress(list.get(0), 0));
						}
					}
					
					continue;
				}
				case "CALL": {
					if(list.size() == 3) {
						Address addr_0 = getAddress(list.get(0), 0);
						Address addr_1 = getAddress(list.get(1), 0);
						Address addr_2 = getAddress(list.get(2), 0);
						
						if(addr_2 == null) {
							// System.out.printf("    : luaL_register( lua_State, table = %s, name = %s )\n", addr_0, addr_1);
							object.importRegister(addr_1, addr_0);
							
							push_find = addr_1;
						} else {
							// System.out.printf("    : CreateUserdata( lua_State, table = %s, userdata = %s, type = %s )\n", addr_0, addr_1, addr_2);
							object.importUserdata(addr_0, addr_1, addr_2);
							
							// TODO: Cache types
							// LuaUtil.addType(addr_2);
						}
					}
				}
			}
			
			list.clear();
		} while(iter != null);
		
		return object;
	}
	
	public Address getAddress(Instruction i, int index) {
		String string = i.getDefaultOperandRepresentation(index);
		if(string.startsWith("0x")) string = string.substring(2);
		return plugin.getCurrentProgram().getAddressFactory().getAddress(string);
	}
}
