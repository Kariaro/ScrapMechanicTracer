package sm.hardcoded.plugin.tracer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.NodeFunction;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.TracedFunction;

class CodeSyntaxTreeAnalyser {
	private final ScrapMechanicPlugin plugin;
	private final CodeSyntaxTreeUtils utils;
	
	public CodeSyntaxTreeAnalyser(ScrapMechanicPlugin tool) {
		this.plugin = tool;
		this.utils = new CodeSyntaxTreeUtils(tool);
	}
	
//	public void analyse(SMClass.Function func) {
//		Program currentProgram = plugin.getCurrentProgram();
//		if(currentProgram == null) return;
//		
//		AddressFactory addressFactory = currentProgram.getAddressFactory();
//		if(addressFactory == null) {
//			Msg.error(this, "getAddressFactory() returned 'null'");
//			return;
//		}
//		
//		Address address = addressFactory.getAddress(func.getAddress());
//		provider = plugin.getWindow();
//		provider.writeLog(this, "Working on the address -> " + address);
//		
//		CodeSyntaxResolver resolver = new CodeSyntaxResolver(this, plugin);
//		CodeSyntaxTreeUnit unit = resolver.start(utils, new NodeFunction(address, 0, utils.getVarnode("stack", 0x4, 4)), 2);
//		
//		TracedFunction trace = unit.getTrace();
//		System.out.println(trace);
//	}
	private Varnode stackVarnode;
	
	public void init() {
		stackVarnode = utils.getVarnode("stack", 0x4, 4);
	}
	
	public TracedFunction analyse(SMClass.Function func) {
		CodeSyntaxResolver resolver = new CodeSyntaxResolver(this, plugin);
		AddressFactory addressFactory = plugin.getCurrentProgram().getAddressFactory();
		Address address = addressFactory.getAddress(func.getAddress());
		CodeSyntaxTreeUnit unit = resolver.start(
			utils,
			new NodeFunction(address, 0, stackVarnode),
			2
		);
		
		return unit.getTrace();
	}
	
	public boolean discoverCode(Address entry) {
		// Is this the bottle neck?
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return false;
		
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(entry);
		
		if(function == null) {
			DisassembleCommand cmd = new DisassembleCommand(entry, null, true);
			cmd.enableCodeAnalysis(false);
			if(!cmd.applyTo(currentProgram)) {
				Msg.warn(this, "Failed to disassemble memory at address '" + entry + "'");
			}
			
			function = functionManager.getFunctionAt(entry);
			
			if(function == null) {
				CreateFunctionCmd cfcmd = new CreateFunctionCmd(entry);
				
				if(!cfcmd.applyTo(currentProgram, TaskMonitor.DUMMY)) {
					Msg.error(this, "(1) Failed to create function at address '" + entry + "'");
					Msg.error(this, "MESSAGE: " + cfcmd.getStatusMsg());
					return false;
				} else {
					function = cfcmd.getFunction();
				}
				
				if(function == null) {
					Msg.error(this, "(2) Failed to create function at address '" + entry + "'");
					Msg.error(this, "MESSAGE: " + cfcmd.getStatusMsg());
					return false;
				}
			}
		}
		
		return true;
	}
}
