package sm.util;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import sm.SMObject;

// https://htmlpreview.github.io/?https://github.com/dragonGR/Ghidra/blob/master/Ghidra/Features/Base/src/main/help/help/topics/AutoAnalysisPlugin/AutoAnalysis.htm
public class SMUtil {
	private static final String PUSH = "PUSH";
	private static final String CALL = "CALL";
	
	// TODO: Run DecompilerParameterIdCmd on only the selected
	//       script functions with an iterated depth of 'x'
	
	// TODO: Cache this class.
	public static SMObject loadSMObject(LuaReg reg) throws MemoryAccessException {
		Address entry = Util.getAddress(reg.func);
		Instruction iter = Util.getInstructionAt(entry);
		
		if(iter == null) {
			// TODO: Check it it needs to be decompiled...
			//AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(Util.getProgram());
			//mgr.disassemble(entry);
			
			DisassembleCommand command = new DisassembleCommand(entry, null, true);
			boolean status = command.applyTo(Util.getProgram(), Util.getMonitor());
			
			System.out.println("Status: " + status);
			iter = Util.getInstructionAt(entry);
		}
		
		Function func = reg.getFunction();
		SMObject object = new SMObject(reg.getBase(), func);
		
		// System.out.println("Function: " + func);
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
		} while(iter != null);
		list.clear();
		
		return object;
	}
	
	/*
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
	*/
	
	private static Address getAddress(Instruction inst) {
		String string = inst.toString();
		String sub = string.substring(string.indexOf("0x") + 2);
		return Util.getAddress(sub);
	}
}
