package sm.hardcoded.plugin.tracer;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
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
	
	public void analyse(SMClass.Function func) {
		currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return;
		
		functionManager = currentProgram.getFunctionManager();
		if(functionManager == null) {
			Msg.error(this, "getFunctionManager() returned 'null'");
			return;
		}

		AddressFactory factory = currentProgram.getAddressFactory();
		Address address = factory.getAddress(func.getAddress());
		provider = plugin.getWindow();
		provider.writeLog(this, "Working on the address -> " + address);
		
		// The max search depth
		int search_depth = 2;
		
		// A unit that processes and solves a lua function
		CodeSyntaxTreeUnit unit = new CodeSyntaxTreeUnit(utils);
		
		List<NodeFunction> list = List.of(new NodeFunction(address, true, 0));
		for(int i = 0; i < search_depth; i++) {
			// Debug
			System.out.println("=======================================");
			System.out.println("List: " + list);
			
			// Keep going lower and lower
			list = discoverLua(unit, list);
			
			// If we dont have any more elements we end the loop 
			if(list.isEmpty()) break;
		}
		
		TracedFunction trace = unit.getTrace();
		System.out.println(trace);
	}
	
	private ScrapMechanicWindowProvider provider;
	private FunctionManager functionManager;
	private Program currentProgram;
	
	private List<NodeFunction> discoverLua(CodeSyntaxTreeUnit unit, List<NodeFunction> nodes) {
		List<NodeFunction> result = new ArrayList<>();
		
		for(NodeFunction node : nodes) {
			result.addAll(discoverLua(unit, node));
		}
		
		return result;
	}
	
	private List<NodeFunction> discoverLua(CodeSyntaxTreeUnit unit, NodeFunction node) {
		if(!discoverCode(node.address)) {
			provider.writeLog(this, "Failed to discover code at [ " + node.address + " ]");
			return List.of();
		}
		
		// Reset some variables
		unit.clean();
		
		Function function = functionManager.getFunctionAt(node.address);
		DecompInterface decomp = new DecompInterface();
		try {
			decomp.toggleCCode(false);
			decomp.toggleJumpLoads(false);
			decomp.openProgram(currentProgram);
			
			DecompileResults result = decomp.decompileFunction(function, 10, TaskMonitor.DUMMY);
			if(!result.decompileCompleted()) {
				Msg.error(this, "MESSAGE: " + result.getErrorMessage());
			}
			
			HighFunction hf = result.getHighFunction();
			for(PcodeBlockBasic block : hf.getBasicBlocks()) {
				Iterator<PcodeOp> iter = block.getIterator();
				while(iter.hasNext()) {
					unit.process(hf, node, iter.next());
				}
			}
		} catch(Exception e) {
			decomp.closeProgram();
			Msg.error(this, "MESSAGE: " + decomp.getLastMessage());
		} finally {
			decomp.closeProgram();
		}
		
		return unit.getFunctionsCopy();
	}
	
	
	
//	public CodeSyntaxTree createSyntaxTree(SMClass.Function func) {
//		Program currentProgram = plugin.getCurrentProgram();
//		if(currentProgram == null) return null;
//		
//		AddressFactory factory = currentProgram.getAddressFactory();
//		Address entry = factory.getAddress(func.getAddress());
//		return createSyntaxTree(entry);
//	}
	
	public CodeSyntaxTree createSyntaxTree(Address entry) {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return null;
		
		Instruction[][] branches = null;
		
		ScrapMechanicWindowProvider provider = plugin.getWindow();
		Listing listing = currentProgram.getListing();
		
		LinkedList<Address> search = new LinkedList<>();
		search.add(entry);
		
		Set<Address> searched = new HashSet<>();
		Set<Address> jumps = new HashSet<>();
		
		do {
			Address current = search.poll();
			Instruction inst = listing.getInstructionAt(current);
			if(inst == null) {
				provider.writeLog(this, "ERROR: Read instruction was null at address '" + current + "'");
				return null;
			}
			
			for(int i = 0; i < 10000; i++) {
				if(searched.contains(inst.getAddress())) {
					inst = inst.getNext();
					continue;
				}
				
				searched.add(current);
				Instruction c = inst;
				
				if(isJumpInstruction(c)) {
					Address branch = inst.getAddress(0);
					if(!jumps.contains(branch)) {
						jumps.add(branch);
						search.add(branch);
					}
				}
				
				if(isReturnInstruction(c)) {
					break;
				}
				
				inst = inst.getNext();
			}
		} while(!search.isEmpty());
		
		List<Address> sorted = new ArrayList<>(jumps);
		sorted.add(entry);
		Collections.sort(sorted);
		
		if(sorted.size() > 10000) {
			provider.writeLog(this, "WARNING: INSANE BRANCHING '" + sorted.size() + "' branches!!!");
			return null;
		}
		
		branches = new Instruction[sorted.size()][];
		
		for(int i = 0; i < sorted.size(); i++) {
			List<Instruction> found = new ArrayList<>();
			Address addr = sorted.get(i);
			int limit = 10000;
			if(i + 1 < sorted.size()) {
				limit = (int)(sorted.get(i + 1).subtract(addr));
			}
			
			Instruction inst = listing.getInstructionAt(addr);
			if(inst == null) {
				provider.writeLog(this, "ERROR: Read instruction was null at address '" + addr + "'");
				return null;
			}
			
			boolean breakBranch = false;
			int max = limit;
			do {
				found.add(inst);
				
				String mnemonic = inst.getMnemonicString();
				if(mnemonic.equals("NOP")
				|| mnemonic.equals("LOCK")) {
					found.remove(found.size() - 1);
				}
				
				if(mnemonic.equals("JMP")) {
					breakBranch = true;
					break; // Unconditional jump.
				}
				
				if(mnemonic.equals("RET")) {
					breakBranch = true;
					break; // Return
				}
				
				if(mnemonic.equals("CALL")) {
					
				}
				
				inst = inst.getNext();
				long offset = inst.getAddress().subtract(addr);
				if(offset >= limit) {
					break; // Branch ends
				}
			} while(max-- > 0);
			
			if(!breakBranch && i + 1 < sorted.size()) {
				//found.add(new JmpInst(sorted.get(i + 1)));
			}
			
			branches[i] = found.toArray(Instruction[]::new);
		}
		
		return new CodeSyntaxTree(branches);
	}
	
	public boolean discoverCode(Address entry) {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return false;
		
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(entry);
		
		{
			DisassembleCommand cmd = new DisassembleCommand(entry, null, true);
			cmd.enableCodeAnalysis(false);
			if(!cmd.applyTo(currentProgram)) {
				Msg.warn(this, "Failed to disassemble memory at address '" + entry + "'");
			}
			
			if(function == null) {
				CreateFunctionCmd cfcmd = new CreateFunctionCmd(entry);
				
				if(!cfcmd.applyTo(currentProgram, TaskMonitor.DUMMY)) {
					Msg.error(this, "Failed to create function at address '" + entry + "'");
					Msg.error(this, "MESSAGE: " + cfcmd.getStatusMsg());
					return false;
				} else {
					function = cfcmd.getFunction();
				}
				
				if(function == null) {
					Msg.error(this, "2 Failed to create function at address '" + entry + "'");
					Msg.error(this, "2 MESSAGE: " + cfcmd.getStatusMsg());
					return false;
				}
			}
		}
		
		return true;
	}
	
	private boolean isJumpInstruction(Instruction i) {
		String mnemonic = i.getMnemonicString();
		switch(mnemonic) {
			case "JMP":
			case "JA":
			case "JAE":
			case "JB":
			case "JBE":
			case "JC":
			case "JCXZ":
			case "JECXZ":
			case "JE":
			case "JG":
			case "JGE":
			case "JL":
			case "JLE":
			case "JNA":
			case "JNAE":
			case "JNB":
			case "JNBE":
			case "JNC":
			case "JNE":
			case "JNG":
			case "JNGE":
			case "JNL":
			case "JNLE":
			case "JNO":
			case "JNP":
			case "JNS":
			case "JNZ":
			case "JO":
			case "JP":
			case "JPE":
			case "JPO":
			case "JS":
			case "JZ":
				return true;
		}
		
		return false;
	}
	
	private boolean isReturnInstruction(Instruction i) {
		String mnemonic = i.getMnemonicString();
		switch(mnemonic) {
			case "RET":
				return true;
		}
		
		return false;
	}
	
	public static class CodeSyntaxTree {
		private final Instruction[][] branches;
		
		private CodeSyntaxTree(Instruction[][] branches) {
			this.branches = branches;
		}
		
		public int getNumBranches() {
			return branches.length;
		}
		
		public Instruction[] getBranch(int index) {
			return branches[index];
		}
	}
	
//	private class CodeBlock {
//		private final PcodeBlockBasic block;
//		private final List<PcodeOp> list;
//		
//		public CodeBlock(PcodeBlockBasic block) {
//			List<PcodeOp> list = new ArrayList<>();
//			Iterator<PcodeOp> iter = block.getIterator();
//			while(iter.hasNext()) list.add(iter.next());
//			this.list = List.copyOf(list);
//			this.block = block;
//		}
//		
//		public String toString() {
//			return block.toString();
//		}
//	}
}
