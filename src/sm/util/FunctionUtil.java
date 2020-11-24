package sm.util;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import sm.complex.ScrapMechanic;

@Deprecated(forRemoval = true)
public final class FunctionUtil {
	private FunctionUtil() {
		
	}
	
	public static Function createFunction(Address entry) throws Exception {
		return createFunction(entry, true, false);
	}
	
	public static Function createFunction(Address entry, boolean dissasemble, boolean decompileParameterId) throws Exception {
		Function func = Util.getFunctionManager().getFunctionAt(entry);
		boolean status;
		
		if(func != null) {
			if(decompileParameterId) {
				DecompilerParameterIdCmd command_2 = new DecompilerParameterIdCmd(
					func.getBody(), SourceType.IMPORTED, true, true,
					ScrapMechanic.DECOMPILE_TIMEOUT
				);
				status = command_2.applyTo(Util.getProgram(), Util.getMonitor());
				
				if(!status) {
					throw new Exception("Failed to decompile parameter id ' " + entry + " '");
				}
			}
			
			return func;
		}
		
		if(dissasemble) {
			DisassembleCommand command_0 = new DisassembleCommand(entry, null, true);
			//command_0.enableCodeAnalysis(false);
			status = command_0.applyTo(Util.getProgram(), Util.getMonitor());
			
			if(!status) {
				throw new Exception("Failed to dissassemble address ' " + entry + " '");
			}
		}
		
		CreateFunctionCmd command_1 = new CreateFunctionCmd(entry, true);
		status = command_1.applyTo(Util.getProgram(), Util.getMonitor());
		
		if(!status) {
			System.out.println("MESSAGE -> '" + command_1.getStatusMsg() + "'");
			throw new Exception("Failed to create new function at address ' " + entry + " '");
		}
		
		func = command_1.getFunction();
		if(func == null) return null;
		
		if(decompileParameterId) {
			DecompilerParameterIdCmd command_2 = new DecompilerParameterIdCmd(
				func.getBody(), SourceType.IMPORTED, true, true,
				ScrapMechanic.DECOMPILE_TIMEOUT
			);
			status = command_2.applyTo(Util.getProgram(), Util.getMonitor());
			
			if(!status) {
				throw new Exception("Failed to decompile parameter id ' " + entry + " '");
			}
		}
		
		return func;
	}

	public static Function createExternalFunction(Address entry, String name) throws InvalidInputException, OverlappingFunctionException {
		GhidraScript script = Util.getScript();
		Function function = script.getFunctionAt(entry);
		// System.out.println("Create0: " + function);
		
		if(function == null) {
			function = script.createFunction(entry, name);
			// System.out.println("Create1: " + function);
			return function;
		}
		
		return function;
	}
	
	public static Function getFunctionAt(Address entry) {
		GhidraScript script = Util.getScript();
		
		Function function = script.getFunctionAt(entry);
		if(function == null) {
			return script.createFunction(entry, "FUN_" + entry);
		}
		
		return function;
	}
	
	public static Function getFunctionAt(String entry) {
		return getFunctionAt(Util.getAddress(entry));
	}
}
