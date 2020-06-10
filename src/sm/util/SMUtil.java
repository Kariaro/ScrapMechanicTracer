package sm.util;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import sm.SMObject;

public class SMUtil {
	private static final String PUSH = "PUSH";
	private static final String CALL = "CALL";
	
	/* TODO: Check if this method has any errors
	 */
	public static SMObject loadSMObject(LuaReg reg) throws MemoryAccessException {
		Address entry = Util.getAddress(reg.func);
		Instruction iter = Util.getInstructionAt(entry);
		
		if(iter == null) {
			DisassembleCommand command = new DisassembleCommand(entry, null, true);
			command.applyTo(Util.getProgram(), Util.getMonitor());
			
			iter = Util.getInstructionAt(entry);
		}
		
		Function func = reg.getFunction();
		SMObject object = new SMObject(reg.getBase(), func);
		
		System.out.println("Function: " + func);
		System.out.println("Entry: " + func.getEntryPoint());

		System.out.println("Instruction: " + iter);

		System.out.println("Body: " + func.getBody());
		List<Instruction> list = new ArrayList<>();
		
		int length = Util.getFunctionLength(func);
		Address push_find = null;
		
		
		do {
			iter = iter.getNext();
			Address addr = iter.getAddress();
			if(Util.getOffset(func, addr) > length) break;
			
			String mnemonic = iter.getMnemonicString();
			System.out.println(iter);
			if(PUSH.equals(mnemonic)) {
				list.add(iter);
				
				if(push_find != null) {
					Address check = iter.getAddress(0);
					
					if(push_find.equals(check)) {
						System.out.println("    : Constant address -> " + list.get(0).getAddress(0));
						object.importConstant(list.get(0).getAddress(0));
					}
				}
			} else {
				if(CALL.equals(mnemonic)) {
					if(list.size() == 3) {
						Address addr_0 = getAddress(list.get(0));
						Address addr_1 = getAddress(list.get(1));
						Address addr_2 = getAddress(list.get(2));
						
						if(addr_2 == null) {
							System.out.printf("    : luaL_register( lua_State, table = %s, name = %s )\n", addr_0, addr_1);
							System.out.println(list);
							
							InstructionDB test = (InstructionDB)list.get(0);
							System.out.println(test);
							System.out.println(test.getClass());
							object.importRegister(addr_1, addr_0);
							
							// Check for addr_1 in push after this point to get InitializeSmVariable
							push_find = addr_1;
						} else {
							System.out.printf("    : CreateUserdata( lua_State, table = %s, userdata = %s, type = %s )\n", addr_0, addr_1, addr_2);
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
	
	static class BasicDecompileConfigurer implements DecompileConfigurer {
		private Program program;

		public BasicDecompileConfigurer(Program program) {
			this.program = program;
		}

		public void configure(DecompInterface decomp) {
			decomp.setSimplificationStyle("decompile");
			decomp.toggleSyntaxTree(true);
			decomp.toggleCCode(true);
			
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(program);
			decomp.setOptions(opts);
		}
	}
	
	private static Address getAddress(Instruction inst) {
		String string = inst.toString();
		String sub = string.substring(string.indexOf("0x") + 2);
		return Util.getAddress(sub);
	}
}
