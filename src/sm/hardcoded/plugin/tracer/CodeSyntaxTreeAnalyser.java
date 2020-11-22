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
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

class CodeSyntaxTreeAnalyser {
	private final ScrapMechanicPlugin plugin;
	public CodeSyntaxTreeAnalyser(ScrapMechanicPlugin tool) {
		plugin = tool;
	}
	
	public void analyse(SMClass.Function func) {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return;
		
		AddressFactory factory = currentProgram.getAddressFactory();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		ScrapMechanicWindowProvider provider = plugin.getWindow();
		Address entry = factory.getAddress(func.getAddress());
		
		
		provider.writeLog(this, "Working on the address -> " + entry);
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
					
					return;
				} else {
					function = cfcmd.getFunction();
				}
				
				provider.writeLog(this, "cfc 0 -> " + cfcmd.getFunction());
				provider.writeLog(this, "cfc 1 -> " + cfcmd.getName());
				provider.writeLog(this, "cfc 2 -> " + cfcmd.getStatusMsg());
				
				if(function == null) {
					Msg.error(this, "2 Failed to create function at address '" + entry + "'");
					Msg.error(this, "2 MESSAGE: " + cfcmd.getStatusMsg());
					return;
				}
			}
		}
		
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
			provider.writeLog(this, "HighFunction: " + hf);
			
			// @SuppressWarnings("deprecation")
			// VarnodeBank vbank = hf.getVbank();
			// provider.writeLog(this, "  VarnodeBank: " + vbank);
			// provider.writeLog(this, "    .size()    -> " + vbank.size());
			// provider.writeLog(this, "    .isEmpty() -> " + vbank.isEmpty());
			
			provider.writeLog(this, "Printing Syntax Trees");
			
			// NOTE - function.getCalledFunctions(TaskMonitor.DUMMY);
			
			List<PcodeBlockBasic> list = hf.getBasicBlocks();
			int index = 0;
			for(PcodeBlockBasic basic : list) {
				int i_size = basic.getInSize();
				int o_size = basic.getOutSize();
				provider.writeLog(this, " Block: " + index + " " + basic);
				
				provider.writeLog(this, "  Inputs:");
				for(int i = 0; i < i_size; i++) {
					PcodeBlock block = basic.getIn(i);
					provider.writeLog(this, "    (" + i + "): " + block);
				}
				
				provider.writeLog(this, "  Outputs:");
				for(int i = 0; i < o_size; i++) {
					PcodeBlock block = basic.getOut(i);
					provider.writeLog(this, "    (" + i + "): " + block);
				}
				
				if(index > 300) break;
				index ++;
			}

			
			/*int index = 0;
			while(iter.hasNext()) {
				//VarnodeAST ast = iter.next();
				PcodeOpAST ast = iter.next();
				
				//Iterator<PcodeOp> descend = ast.getBasicIter();//ast.getDescendants();
				
				provider.writeLog(this, " (" + index + ") " + ast);
				/*int id = 0;
				while(descend.hasNext()) {
					PcodeOp op = descend.next();
					provider.writeLog(this, "   (" + id + ") " + op);
					id ++;
				}*/
				
				/*
				HighVariable hv = ast.getHigh();
				provider.writeLog(this, "   " + hv);
				if(hv != null) {
					provider.writeLog(this, "     " + hv.getName());
					provider.writeLog(this, "     " + hv.getStorage());
				}
				
				if(index > 300) break;
				index ++;
			}
			*/
			
		} catch(Exception e) {
			decomp.closeProgram();
			Msg.error(this, "MESSAGE: " + decomp.getLastMessage());
			
			throw e;
		} finally {
			decomp.closeProgram();
		}
		
		/*CodeSyntaxTree tree = createSyntaxTree(function);
		
		StringBuilder sb = new StringBuilder();
		for(Instruction[] branch : tree.branches) {
			if(branch.length > 0) {
				sb.append("LAB_").append(branch[0].getAddress()).append(" :\n");
			}
			
			for(Instruction inst : branch) {
				sb.append("    ").append(inst).append("\n");
			}
		}
		sb.append("--------------------------------------------------\n");
		
		String string = sb.toString();
		Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
		clip.setContents(new StringTransferable(string), null);
		
		for(Instruction[] branch : tree.branches) {
			if(branch.length < 1) continue;
			
			for(Instruction inst : branch) {
				
				if(isJumpInstruction(inst)) {
					provider.writeLog(this, "JUMP: " + inst);
					
					
				}
			}
		}*/
	}
	
	private CodeSyntaxTree createSyntaxTree(SMClass.Function func) {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return null;
		
		Instruction[][] branches = null;
		
		AddressFactory factory = currentProgram.getAddressFactory();
		ScrapMechanicWindowProvider provider = plugin.getWindow();
		Address entry = factory.getAddress(func.getAddress());
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
	
	static class CodeSyntaxTree {
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
}
