package sm.util;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import sm.complex.ScrapMechanic;

public final class FunctionUtil {
	private FunctionUtil() {
		
	}
	
	public static Function createFunction(Address entry) throws Exception {
		return createFunction(entry, false);
	}
	
	public static Function createFunction(Address entry, boolean decompileParameterId) throws Exception {
		// TODO: Do not compute anything if the function already exists.
		// TODO: Put this in a util class...
		
		Function func = Util.getFunctionManager().getFunctionAt(entry);
		if(func != null) return func;
		
		DisassembleCommand command_0 = new DisassembleCommand(entry, null, true);
		command_0.enableCodeAnalysis(false);
		boolean status = command_0.applyTo(Util.getProgram(), Util.getMonitor());
		
		if(!status) {
			throw new Exception("Failed to dissassemble address ' " + entry + " '");
		}
		
		CreateFunctionCmd command_1 = new CreateFunctionCmd(entry);
		status = command_1.applyTo(Util.getProgram(), Util.getMonitor());
		
		if(!status) {
			throw new Exception("Failed to create new function at address ' " + entry + " '");
		}
		
		func = command_1.getFunction();
		DecompilerParameterIdCmd command_2 = new DecompilerParameterIdCmd(
			func.getBody(), SourceType.IMPORTED, true, true,
			ScrapMechanic.DECOMPILE_TIMEOUT
		);
		status = command_2.applyTo(Util.getProgram(), Util.getMonitor());
		
		if(!status) {
			throw new Exception("Failed to decompile parameter id ' " + entry + " '");
		}
		
		return func;
	}
}
