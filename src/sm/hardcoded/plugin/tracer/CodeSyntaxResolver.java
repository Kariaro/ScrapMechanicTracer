package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeAnalyser.NodeFunction;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeAnalyser.TracedFunction;

/**
 * It is important that this class is not called from multiple threads
 * 
 * @author HardCoded
 * @date 2020-11-25
 */
class CodeSyntaxResolver {
	private final CodeSyntaxTreeAnalyser cta;
	private final DecompInterface decomp;
	private final ScrapMechanicWindowProvider provider;
	private final FunctionManager functionManager;
	private final Program currentProgram;
	private boolean debug;
	
	public CodeSyntaxResolver(CodeSyntaxTreeAnalyser cta, DecompInterface decomp) {
		this.cta = cta;
		this.decomp = decomp;
		
		functionManager = cta.functionManager;
		currentProgram = cta.currentProgram;
		provider = cta.plugin.getWindow();
	}
	
	public void setDebug(boolean enable) {
		this.debug = enable;
	}
	
	public TracedFunction analyse(SMClass.Function func, int depth) {
		return start(
			new NodeFunction(
				cta.getAddress(func.getAddress()),
				0,
				cta.stackVarnode
			), depth
		).getTrace();
	}
	
	public CodeSyntaxTreeUnit start(NodeFunction start, int depth) {
		CodeSyntaxTreeUnit unit = new CodeSyntaxTreeUnit(cta);
		unit.setDebug(debug);
		
		try {
			List<NodeFunction> list = List.of(start);
			for(int i = 0; i < depth; i++) {
				AddressSet fullSet = new AddressSet();
				
				for(NodeFunction parent : list) {
					List<NodeFunction> children = findChildrenBasic(unit, parent);
					fullSet.add(getAddressSet(parent, children));
				}
				
				// Rescan the function now that we have discovered the parameter ids
				DecompilerParameterIdCmd decompId = new DecompilerParameterIdCmd(fullSet, SourceType.ANALYSIS, true, true, 400);
				if(!decompId.applyTo(currentProgram)) {
					System.out.println("Failed to decompile parameter message: " + decompId.getStatusMsg());
				}
				
				List<NodeFunction> combined = new ArrayList<>();
				for(NodeFunction parent : list) {
					if(debug) System.out.println(parent);
					combined.addAll(findChildren(unit, parent));
				}
				
				if(debug) {
					System.out.println(combined);
				}
				
				if(combined.isEmpty()) break;
				list = combined;
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return unit;
	}
	
	private List<NodeFunction> findChildren(CodeSyntaxTreeUnit unit, NodeFunction node) {
		// Clean function variable
		unit.clean();
		
		try {
			Function function = functionManager.getFunctionAt(node.address);
			decomp.setSimplificationStyle("decompile");
			DecompileResults result = decomp.decompileFunction(function, 20, TaskMonitor.DUMMY);
			if(!result.decompileCompleted()) {
				throw new Exception("Failed decompile the function at [ " + node.address + " ] " + result.getErrorMessage());
			}
			
			node.high = result.getHighFunction();
			for(PcodeBlockBasic block : result.getHighFunction().getBasicBlocks()) {
				Iterator<PcodeOp> iter = block.getIterator();
				while(iter.hasNext()) {
					unit.process(node, iter.next());
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return unit.getFunctionsCopy();
	}
	
	private List<NodeFunction> findChildrenBasic(CodeSyntaxTreeUnit unit, NodeFunction node) {
		if(!cta.discoverCode(node.address)) {
			provider.writeLog(this, "Failed to discover code at [ " + node.address + " ]");
			return List.of();
		}
		
		// Clean function variable
		unit.clean();
		
		try {
			Function function = functionManager.getFunctionAt(node.address);
			decomp.setSimplificationStyle("firstpass");
			DecompileResults result = decomp.decompileFunction(function, 10, TaskMonitor.DUMMY);
			if(!result.decompileCompleted()) {
				throw new Exception("Failed decompile the function at [ " + node.address + " ] " + result.getErrorMessage());
			}
			
			node.high = result.getHighFunction();
			for(PcodeBlockBasic block : result.getHighFunction().getBasicBlocks()) {
				Iterator<PcodeOp> iter = block.getIterator();
				while(iter.hasNext()) {
					unit.process_basic(node, iter.next());
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
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