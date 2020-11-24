package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.NodeFunction;

/**
 * It is important that this class is not called from multiple threads
 * 
 * @author HardCoded
 * @date 2020-11-24
 */
class CodeSyntaxResolver {
	private final CodeSyntaxTreeAnalyser cta;
	private final DecompInterface decomp;
	private volatile boolean closed;
	
	private ScrapMechanicWindowProvider provider;
	private FunctionManager functionManager;
	private AddressFactory addressFactory;
	private Program currentProgram;
	
	private CodeSyntaxTreeUnit unit;
	
	public CodeSyntaxResolver(CodeSyntaxTreeAnalyser cta, ScrapMechanicPlugin plugin) {
		this.cta = cta;
		
		// Setup the decompiler.
		decomp = new DecompInterface();
		decomp.toggleCCode(false);
		decomp.toggleJumpLoads(false);
		
		currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) throw new NullPointerException("plugin.getCurrentProgram() was null");
		
		functionManager = currentProgram.getFunctionManager();
		if(functionManager == null) throw new NullPointerException("currentProgram.getFunctionManager() was null");
		
		addressFactory = currentProgram.getAddressFactory();
		if(addressFactory == null) throw new NullPointerException("currentProgram.getAddressFactory() was null");
		
		provider = plugin.getWindow();
	}
	
//	public CodeSyntaxTreeUnit start(CodeSyntaxTreeUtils utils, NodeFunction start, int depth) {
//		if(closed) throw new IllegalArgumentException("This class is already closed");
//		this.closed = true;
//		this.unit = new CodeSyntaxTreeUnit(utils);
//		
//		try {
//			if(!decomp.openProgram(currentProgram)) {
//				throw new Exception("Failed to open program [ " + currentProgram + " ] : " + decomp.getLastMessage());
//			}
//
//			List<NodeFunction> list = List.of(start);
//			for(int i = 0; i < depth; i++) {
////				System.out.println("=======================================");
////				System.out.println("List: " + list);
//				
//				List<NodeFunction> combined = new ArrayList<>();
//				for(NodeFunction parent : list) {
//					List<NodeFunction> children = findChildrenBasic(parent);
//					AddressSet set = getAddressSet(parent, children);
//					
//					DecompilerParameterIdCmd decompId = new DecompilerParameterIdCmd(set, SourceType.ANALYSIS, true, true, 400);
//					if(!decompId.applyTo(currentProgram)) {
//						System.out.println("Failed to decompile parameter message: " + decompId.getStatusMsg());
//					}
//					
//					// Rescan the function now that we have discovered the parameter ids
//					combined.addAll(findChildren(parent));
//				}
//				
//				if(combined.isEmpty()) break;
//				list = combined;
//			}
//		} catch(Exception e) {
//			decomp.closeProgram();
//			e.printStackTrace();
//			Msg.error(this, "MESSAGE: " + decomp.getLastMessage());
//		} finally {
//			decomp.closeProgram();
//		}
//		
//		return this.unit;
//	}
	
	public CodeSyntaxTreeUnit start(CodeSyntaxTreeUtils utils, NodeFunction start, int depth) {
		if(closed) throw new IllegalArgumentException("This class is already closed");
		this.closed = true;
		this.unit = new CodeSyntaxTreeUnit(utils);
		
		try {
			if(!decomp.openProgram(currentProgram)) {
				throw new Exception("Failed to open program [ " + currentProgram + " ] : " + decomp.getLastMessage());
			}

			List<NodeFunction> list = List.of(start);
			for(int i = 0; i < depth; i++) {
				AddressSet fullSet = new AddressSet();
				
				for(NodeFunction parent : list) {
					List<NodeFunction> children = findChildrenBasic(parent);
					fullSet.add(getAddressSet(parent, children));
				}
				
				// Rescan the function now that we have discovered the parameter ids
				DecompilerParameterIdCmd decompId = new DecompilerParameterIdCmd(fullSet, SourceType.ANALYSIS, true, true, 400);
				if(!decompId.applyTo(currentProgram)) {
					System.out.println("Failed to decompile parameter message: " + decompId.getStatusMsg());
				}
				
				List<NodeFunction> combined = new ArrayList<>();
				for(NodeFunction parent : list) {
					combined.addAll(findChildren(parent));
				}
				
				if(combined.isEmpty()) break;
				list = combined;
			}
		} catch(Exception e) {
			decomp.closeProgram();
			e.printStackTrace();
			Msg.error(this, "MESSAGE: " + decomp.getLastMessage());
		} finally {
			decomp.closeProgram();
		}
		
		return this.unit;
	}
	
	private List<NodeFunction> findChildrenBasic(NodeFunction node) {
		if(!cta.discoverCode(node.address)) {
			provider.writeLog(this, "Failed to discover code at [ " + node.address + " ]");
			return List.of();
		}
		
		// Clean function variable
		unit.clean();
		
		try {
			Function function = functionManager.getFunctionAt(node.address);
			DecompileResults result = decomp.decompileFunction(function, 10, TaskMonitor.DUMMY);
			if(!result.decompileCompleted()) {
				throw new Exception("Failed decompile the function at [ " + node.address + " ]");
			}
			
			for(PcodeBlockBasic block : result.getHighFunction().getBasicBlocks()) {
				Iterator<PcodeOp> iter = block.getIterator();
				while(iter.hasNext()) {
					unit.process_basic(node, iter.next());
				}
			}
		} catch(Exception e) {
			Msg.error(this, "MESSAGE: " + decomp.getLastMessage());
		}
		
		return unit.getFunctionsCopy();
	}
	
	private List<NodeFunction> findChildren(NodeFunction node) {
		// Clean function variable
		unit.clean();
		
		try {
			Function function = functionManager.getFunctionAt(node.address);
			DecompileResults result = decomp.decompileFunction(function, 10, TaskMonitor.DUMMY);
			if(!result.decompileCompleted()) {
				throw new Exception("Failed decompile the function at [ " + node.address + " ]");
			}
			
			for(PcodeBlockBasic block : result.getHighFunction().getBasicBlocks()) {
				Iterator<PcodeOp> iter = block.getIterator();
				while(iter.hasNext()) {
					unit.process(node, iter.next());
				}
			}
		} catch(Exception e) {
			Msg.error(this, "MESSAGE: " + decomp.getLastMessage());
		}
		
		return unit.getFunctionsCopy();
	}
	
	private AddressSet getAddressSet(NodeFunction parent, List<NodeFunction> list) {
		AddressSet set = new AddressSet();
		
		Function function = functionManager.getFunctionAt(parent.address);
		if(function != null) set.add(function.getBody());
		
		for(NodeFunction node : list) {
			if(cta.discoverCode(node.address)) {
				function = functionManager.getFunctionAt(node.address);
				if(function != null) set.add(function.getBody());
			}
		}
		
		return set;
	}
}
