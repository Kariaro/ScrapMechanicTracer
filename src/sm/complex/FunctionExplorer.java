package sm.complex;

import static sm.complex.ScrapMechanic.*;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import sm.SMFunctionObject;
import sm.SMLogger;
import sm.util.FunctionUtil;
import sm.util.LuaUtil;
import sm.util.Util;

/**
 * This class will search throuh a decompiled function and try guess the 
 * structure of how it is made.
 * 
 * This is structure is really complicated and is not easy to find.
 * 
 * @author HardCoded
 */
public class FunctionExplorer implements Closeable {
	// TODO: Cache functions by creating small auto functions
	//       (a, b, c) -> List<Command> { processCommand(a, b, c); }
	
	private static final String CALL = "CALL";
	private static final String COPY = "COPY";
	
	private final DataType LUA_STATE_PTR_DATATYPE;
	private final DataType INT_DATATYPE;
	private DecompInterface decomp;
	private boolean isClosed;
	
	public FunctionExplorer() {
		decomp = new DecompInterface();
		decomp.toggleCCode(false);
		decomp.openProgram(Util.getScript().getCurrentProgram());
		
		LUA_STATE_PTR_DATATYPE = Util.getDataTypeManager().getDataType("/lua.h/lua_State *");
		INT_DATATYPE = Util.getDataTypeManager().getDataType("/int");
	}
	
	public AnalysedFunction evaluate(SMFunctionObject object) {
		return evaluate(object.getFunction());
	}
	
	public AnalysedFunction evaluate(String entryPoint) {
		Function function;
		try {
			function = FunctionUtil.createFunction(Util.getAddress(entryPoint), true, true);
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
		
		return evaluate(function);
	}
	
	public AnalysedFunction evaluate(Function function) {
		if(isClosed) return null;
		
		AnalysedFunction fuzzed = new AnalysedFunction();
		
		Varnode[] varnode = new Varnode[1];
		{
			Parameter[] params = function.getParameters();
			
			// TODO: Should the function names be resolved????
			// TODO: What do we do if this fails?
			if(params.length > 0) {
				// Because this is the first function in the evaluation tree
				// this parameter should be a lua_State*
				Parameter param = params[0];
				if(function.getCallingConventionName().equals("__thiscall")) {
					param = params[1];
				}
				
				varnode[0] = param.getFirstStorageVarnode();
				
				if(!function.getReturnType().isEquivalent(INT_DATATYPE)) {
					try {
						function.setReturnType(INT_DATATYPE, SourceType.ANALYSIS);
					} catch(InvalidInputException e) {
						e.printStackTrace();
					}
				}
				
				if(!param.getDataType().equals(LUA_STATE_PTR_DATATYPE)) {
					try {
						param.setDataType(LUA_STATE_PTR_DATATYPE, SourceType.ANALYSIS);
					} catch(InvalidInputException e) {
						e.printStackTrace();
					}
				}
			}
		}
		
		enterFunction(fuzzed, function.getEntryPoint(), 0, varnode);
		
		return fuzzed;
	}
	
	private void enterFunction(AnalysedFunction fuzzed, Address callAddress, int depth, Varnode[] params) {
		if(Util.isMonitorCancelled()) return;

		// Function function = Util.getFunctionAt(callAddress);
		Function function;
		try {
			function = FunctionUtil.createFunction(callAddress, true, true);
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
		
		
		/*
		// TODO: Find a better way of checking if a function is disassembled!
		if(Util.getInstructionAt(callAddress) == null) {
			DisassembleCommand command = new DisassembleCommand(callAddress, null, true);
			command.applyTo(Util.getProgram(), Util.getMonitor());
		}
		*/
		
		if(TRACE) SMLogger.log("Addr: %s, %s", callAddress, function);
		if(function == null) return;
		
		DecompileResults result = decomp.decompileFunction(function, DECOMPILE_TIMEOUT, null);
		HighFunction local = result.getHighFunction();
		if(local == null) {
			/* This is usually the result of a TimeoutException or that the
			 * TaskMonitor was closed.
			 * 
			 * This is because some functions take more than 30 seconds to
			 * complete and they should probably be handled separatly.
			 */
			SMLogger.err("The generated HighFunction was null ! Error: %s", result.getErrorMessage());
			return;
		}
		
		try {
			traverseFunction(fuzzed, local, depth, params);
		} catch(Throwable e) {
			e.printStackTrace();
			//System.out.println(" > " + callAddress);
			//throw new NullPointerException();
		}
	}
	
	private void traverseFunction(AnalysedFunction fuzzed, HighFunction local, int depth, Varnode[] params) {
		List<Instruction> instructions = getCallInstructions(local);
		
		for(int instIndex = 0; instIndex < instructions.size(); instIndex++) {
			Instruction inst = instructions.get(instIndex);
			Address instAddress = inst.getAddress();
			
			// NOTE: What else can you get from this iterator?
			Iterator<PcodeOpAST> iter = local.getPcodeOps(instAddress);
			if(!iter.hasNext()) continue;
			
			PcodeOpAST command = iter.next();
			Address callAddress = command.getInput(0).getAddress();
			
			
			if(LuaUtil.isLuaPointer(callAddress)) {
				String function = LuaUtil.getNameFromPointer(callAddress);
				Varnode[] nextParams = resolveParams(command, local, params);
				
				if(TRACE) {
					SMLogger.log("%s, CALL LUA51::%s", instAddress, function);
					
					for(int i = 0; i < nextParams.length; i++) {
						Varnode node = nextParams[i];
						SMLogger.log("        args[%d]: %s", i, node);
					}
					SMLogger.log();
				}
				
				processCommand(fuzzed, function, command, nextParams);
			} else if(depth < DECOMPILE_MAX_DEPTH) {
				if(TRACE) {
					SMLogger.log("---------------------------------");
				}
				
				// If this is set, the function will compute values downwards.
				boolean traverse = false;
				
				/* Sometime the first function is a check to see if the command is
				 * called from the server or the client.
				 * 
				 * This function does not access the 'lua_State' parameter.
				 * 
				 * This function usually contains the strings
				 *   "Sandbox violation: callback while no sandbox is present."
				 *   "Sandbox violation: calling %s function from %s callback."
				 */
				if(instIndex == 0) {
					if(TRACE) {
						SMLogger.log("        : %s, %s", instAddress, inst);
						SMLogger.log("            : Calling Function: %s", command.getInput(0), callAddress);
						SMLogger.log();
					}
					
					traverse = true;
				}
				
				Varnode[] nextParams = resolveParams(command, local, params);
				for(int i = 0; i < nextParams.length; i++) {
					Varnode node = nextParams[i];
					if(node == null) continue;
					
					Address addr = node.getAddress();
					if(addr.isStackAddress() && addr.getOffset() == 4) {
						traverse = true;
						
						// INFO: Some decompiled code does not work if the parameter is of the wrong type
						//       therefore the parameter needs to be changed to the correct type.
						//
						//       This is not easy because sometimes PcodeOp can smash together values in
						//       an unexpected way. These unexpected values should be discarded because
						//       of complexity.
						//
						// Function nextFunction = Util.getFunctionAt(callAddress);
						Function nextFunction;
						try {
							nextFunction = FunctionUtil.createFunction(callAddress, true, true);
						} catch(Exception e) {
							e.printStackTrace();
							return;
						}
						
						// NOTE: This is really unexpected
						if(nextFunction == null) break;
						
						if(nextFunction.getAutoParameterCount() != 0) {
							nextFunction.setCustomVariableStorage(true);
						}
						
						
						Parameter[] nextFunctionParams = nextFunction.getParameters();
						if(nextFunctionParams.length > i) {
							Parameter param = nextFunctionParams[i];
							
							if(!param.getDataType().isEquivalent(LUA_STATE_PTR_DATATYPE)) {
								try {
									param.setDataType(LUA_STATE_PTR_DATATYPE, SourceType.ANALYSIS);
								} catch(InvalidInputException e) {
									e.printStackTrace();
								}
							}
						}
					}
				}
				
				{
					// Check the 'has been removed' message.
					for(Varnode node : nextParams) {
						if(node == null || !node.isUnique()) continue;
						
						String message = getStringFromUnique(node);
						if(message != null && message.contains("has been removed")) {
							fuzzed.errors.add("$FUNCTION_REMOVED");
							return;
						}
					}
				}
				
				if(traverse) {
					// NOTE: Sometimes arguments are pushed into registers before being pushed to a
					//       call command. The task is to check if any of these registers point to
					//       the current functions parameters. And if so change that value into the
					//       last known parameter value. Otherwise it should be null.
					//
					
					if(TRACE) {
						SMLogger.log("%s, %s", instAddress, inst);
						for(int i = 0; i < nextParams.length; i++) {
							Varnode node = nextParams[i];
							SMLogger.log("        args[%d]: %s", i, node);
						}
						SMLogger.log();
						SMLogger.log("Test: %s, %s", DECOMPILE_MAX_DEPTH, depth);
					}
					
					enterFunction(fuzzed, callAddress, depth + 1, nextParams);
				}
			}
		}
	}
	
	private Varnode[] resolveParams(PcodeOpAST command, HighFunction local, Varnode[] inputs) {
		if(local == null || command.getNumInputs() < 2) return new Varnode[0];
		
		Varnode[] result = new Varnode[command.getNumInputs() - 1];
		Parameter[] params = local.getFunction().getParameters();
		
		for(int i = 1; i < command.getNumInputs(); i++) {
			Varnode node = command.getInput(i);
			// SMLogger.log("        input[%d]: %s", i, node);

			// TODO: This code is duplicated!
			HighVariable hv = node.getHigh();
			if(hv != null) {
				// SMLogger.log("          storage: %s", hv.getStorage());
				// SMLogger.log("          name: %s", hv.getName());
				
				for(int k = 0; k < Math.min(params.length, inputs.length); k++) {
					Parameter param = params[k];
					if(param.getName().equals(hv.getName())) {
						// SMLogger.log("        RESULT[%d]: %s\t -> %s", k, param, inputs[k]);
						result[i - 1] = inputs[k];
						break;
					}
				}
			}
			
			// TODO: For how long do we need to traverse this????
			PcodeOp op = node.getDef();
			if(op != null && op.getNumInputs() > 0) {
				// SMLogger.log("          op: %s", op);
				// SMLogger.log("          op: %s", op.getInput(0));
				
				Varnode node_2 = op.getInput(0);
				if(node_2 != null) {
					HighVariable hv_2 = node_2.getHigh();
					if(hv_2 != null) {
						// TODO: This code is duplicated!
						// SMLogger.log("            storage: %s", hv_2.getStorage());
						// SMLogger.log("            name: %s", hv_2.getName());
						
						for(int k = 0; k < Math.min(params.length, inputs.length); k++) {
							Parameter param = params[k];
							
							if(param.getName().equals(hv_2.getName())) {
								// SMLogger.log("        RESULT[%d]: %s\t -> %s", k, param, inputs[k]);
								result[i - 1] = inputs[k];
								break;
							}
						}
					}
				}
			}
			
			if(result[i - 1] == null) {
				// TODO: What if this node is a stack address ?
				//       That should not be allowed!!
				Address addr = node.getAddress();
				if(addr.isStackAddress()) continue;
				
				result[i - 1] = node;
				
				if(node.isUnique()) {
				}
				
				if(node.isConstant()) {
					result[i - 1] = node;
				}
			}
		}
		
		/*
		SMLogger.log("       RESULTS:");
		for(int i = 0; i < result.length; i++) {
			Varnode node = result[i];
			SMLogger.log("        result[%d]: %s", i, node);
		}
		SMLogger.log();
		*/
		
		return result;
	}
	
	/**
	 * @param set
	 * @return All the call instructions inside the given function.
	 */
	private List<Instruction> getCallInstructions(HighFunction set) {
		List<Instruction> list = new ArrayList<>();
		
		// NOTE: Sometimes function.getBody() returns a zero sized AddressSetView.
		AddressSetView view = set.getFunction().getBody();
		
		//if(view.getMaxAddress().subtract(view.getMinAddress()) == 0) {
			
		//} else {
			List<AddressSet> ranges = new ArrayList<>();
			
			{
				AddressFactory factory = Util.getScript().getAddressFactory();
				for(PcodeBlockBasic basic : set.getBasicBlocks()) {
					//SMLogger.log("  start = " + basic.getStart());
					//SMLogger.log("  stop  = " + basic.getStop());
					
					ranges.add(factory.getAddressSet(basic.getStart(), basic.getStop()));
				}
			}
			
			
			for(AddressSet range : ranges) {
				Instruction inst = Util.getInstructionAt(range.getMinAddress());
				
				while(inst != null) {
					if(!range.contains(inst.getAddress())) break;
					
					// SMLogger.log("%s, %s", inst.getAddress(), inst);
					
					if(CALL.equals(inst.getMnemonicString())) {
						list.add(inst);
					}
					
					inst = inst.getNext();
				}
			}
			
			if(TRACE) SMLogger.log("View: %s", view);
			
			Iterator<AddressRange> memory = view.iterator();
			while(memory.hasNext()) {
				AddressRange range = memory.next();
				if(TRACE) SMLogger.log("Range: %s", range);
				
				Instruction inst = Util.getInstructionAt(range.getMinAddress());
				
				while(inst != null) {
					if(!range.contains(inst.getAddress())) break;
					
					// SMLogger.log("%s, %s", inst.getAddress(), inst);
					
					if(CALL.equals(inst.getMnemonicString())) {
						if(!list.contains(inst)) {
							list.add(inst);
						}
					}
					
					inst = inst.getNext();
				}
			}
		//}
		
		/*
		Instruction inst = Util.getInstructionBefore(set);
		
		while(inst != null) {
			if(!Util.isInside(inst, set)) break;
			
			SMLogger.log("%s, %s", inst.getAddress(), inst);
			
			if(CALL.equals(inst.getMnemonicString())) {
				list.add(inst);
			}
			
			inst = inst.getNext();
		}
		*/
		
		return list;
	}
	
	private boolean checkArgError(AnalysedFunction fuzzed, PcodeOpAST command, Varnode[] newParams) {
		if(newParams.length < 3) return false;
		
		// SMLogger.log("      : len = %s", newParams.length);
		
		Varnode last = newParams[2];
		if(last == null || !last.isRegister()) return false;
		
		PcodeOp op = last.getDef();
		
		if(op == null || !op.getMnemonic().equals(CALL)) return false;
		
		Varnode addr = op.getInput(0);
		// SMLogger.log("      : " + last);
		// SMLogger.log("          : " + op);
		// SMLogger.log("          : addr = " + addr);
		
		Address call_addr = addr.getAddress();
		if(!LuaUtil.isLuaPointer(call_addr)) return false;
		
		String function = LuaUtil.getNameFromPointer(call_addr);
		if(!function.equals("lua_pushfstring")) return false;
		
		if(op.getNumInputs() < 3) return false;
		Varnode test_0 = Util.getPcodeVarnode(op.getInputs(), 2, 0);
		Varnode test_1 = Util.getPcodeVarnode(op.getInputs(), 3, 0);
		if(test_1 == null || test_1 == null) return false;
		
		String msg = getStringFromUnique(test_0.getAddress());
		String type = getStringFromUnique(test_1.getAddress());
		
		
		if(msg.equals("%s expected, got %s")) {
			if(TRACE) {
				SMLogger.log("            msg:  \"%s\"", msg);
				SMLogger.log("            type: \"%s\"", type);
				SMLogger.log("            num: %s", newParams[1].getOffset());
			}
			long index = newParams[1].getOffset();
			
			fuzzed.setArgument(index, type);
			
			return true;
		}
		
		return false;
	}
	
	// TODO: Failes to find argument length sometimes.
	private boolean checkLuaError(AnalysedFunction fuzzed, PcodeOpAST command, Varnode[] newParams) {
		if(command.getNumInputs() < 4) return false;
		
		// SMLogger.log("Testing : %s", command);
		
		//for(int i = 1; i < command.getNumInputs(); i++) {
		//	Varnode input = command.getInput(i);
		//	SMLogger.log("        [%d]: %s", i, input);
		//}
		
		//System.out.println();
		
		PcodeOp[] msgCount = new PcodeOp[4];
		
		for(int i = 2; i < 4; i++) {
			Varnode input = command.getInput(i);
			if(TRACE) SMLogger.log("        [%d]: %s", i, input);
			if(input == null) continue;
			
			HighVariable hv = input.getHigh();
			if(TRACE) SMLogger.log("          high: %s", hv.getName());
			
			int count = 0;
			Varnode[] mem = hv.getInstances();
			for(int j = 0; j < mem.length; j++) {
				Varnode m = mem[j];
				PcodeOp op = m.getDef();
				if(op == null) continue;
				
				if(TRACE) SMLogger.log("              [%d]: %s    %s", j, op, op.getInput(0).getDef());
				
				if(COPY.equals(op.getMnemonic())) {
					msgCount[(i - 2) * 2 + (count++)] = op;
					if(count > 1) break;
				}
			}
			
			//System.out.println();
		}
		
		for(int i = 0; i < 4; i++) {
			if(msgCount[i] == null) return false;
			if(TRACE) SMLogger.log("        [%d]: %s", i, msgCount[i]);
		}
		
		// Read message
		for(int i = 0; i < 2; i++) {
			if(TRACE) SMLogger.log("        [%d]: %s", i, msgCount[i].getInput(0).getOffset());
			String str = Util.readTerminatedString(Util.getAddressFromLong(msgCount[i].getInput(0).getOffset()));
			if(str == null) return false;
			if(TRACE) SMLogger.log("        [%d]: str = %s", i, str);
			
			int args = Util.toSignedInt(msgCount[i + 2].getInput(0).getOffset());
			
			if(TRACE) SMLogger.log("        [%d]: args = %s", i, args);
			if(str.startsWith("Expected %d arguments")) {
				fuzzed.minimumArguments = args;
				fuzzed.maximumArguments = args;
			} else if(str.startsWith("Expected at most %d arguments")) {
				fuzzed.maximumArguments = args;
			} else if(str.startsWith("Expected at least %d arguments")) {
				fuzzed.minimumArguments = args;
			} else {
				// This should never run
				fuzzed.errors.add(str);
			}
		}
		
		return true;
	}
	
	private void processCommand(AnalysedFunction fuzzed, String name, PcodeOpAST command, Varnode[] nextParams) {
		switch(name) {
			case "luaL_checkudata": {
				if(nextParams.length < 3) break;
				long index = nextParams[1].getOffset();
				String str = getStringFromUnique(nextParams[2]);
				if(TRACE) {
					SMLogger.log("  luaL_checkudata(lua_State, %d, \"%s\");", index, str);
				}
				
				fuzzed.setArgument(index, str);
				break;
			}
			case "luaL_checktype": {
				if(nextParams.length < 3) break;
				
				long index = Util.toSignedInt(Util.getPcodeVarnode(nextParams, 1).getOffset());
				long type = Util.toSignedInt(Util.getPcodeVarnode(nextParams, 2).getOffset());
				if(TRACE) {
					SMLogger.log("  luaL_checktype(lua_State, index = %d, type = %d);", index, type);
				}
				
				fuzzed.setArgument(index, LuaUtil.getTypeNameFromId(type));
				return;
			}
			case "luaL_argerror": {
				checkArgError(fuzzed, command, nextParams);
				break;
			}
			case "luaL_error": {
				checkLuaError(fuzzed, command, nextParams);
				
				if(nextParams.length < 3) break;
				String str = getStringFromUnique(nextParams[1]);
				if(TRACE) {
					SMLogger.log("  luaL_error(lua_State, \"%s\");", str);
				}
				
				if(str != null) {
					if(str.startsWith("Expected %d arguments")) {
						int args = Util.toSignedInt(nextParams[2].getOffset());
						fuzzed.minimumArguments = args;
						fuzzed.maximumArguments = args;
					} else if(str.startsWith("Expected at most %d arguments")) {
						int args = Util.toSignedInt(nextParams[2].getOffset());
						fuzzed.maximumArguments = args;
					} else if(str.startsWith("Expected at least %d arguments")) {
						int args = Util.toSignedInt(nextParams[2].getOffset());
						fuzzed.minimumArguments = args;
					} else {
						fuzzed.errors.add(str);
					}
				}
				
				break;
			}
			
			case "luaL_checklstring": {
				if(nextParams.length < 2) break;
				long index = nextParams[1].getOffset();
				fuzzed.setArgument(index, "string");
				return;
			}
			case "luaL_checkinteger": {
				if(nextParams.length < 2) break;
				long index = nextParams[1].getOffset();
				fuzzed.setArgument(index, "integer");
				return;
			}
			case "luaL_checknumber": {
				if(nextParams.length < 2) break;
				long index = nextParams[1].getOffset();
				fuzzed.setArgument(index, "number");
				return;
			}
			case "lua_toboolean": {
				if(nextParams.length < 2) break;
				long index = nextParams[1].getOffset();
				fuzzed.setArgument(index, "boolean");
				return;
			}
			
			// NOTE: By using 'LuaUtil.getTypeNameFromId' this could be used to check what branches
			//       leads to a call to 'luaL_error'.
			case "lua_type": return;
			
			case "lua_getfield": return;
			case "lua_isnumber": return; // NOTE: Should we use this to get additional number variables?
			case "lua_getmetatable": return; // NOTE: Sometimes this is used to create sub tables for returns and other stuff.
			case "lua_typename": return;
			case "lua_topointer": return;
			case "lua_gettop": return; // This function gets the amount of arguments on the stack
			
			default: {
				// Do nothing
			}
		}
		
		/*
		if(TRACE) {
			for(int i = 1; i < nextParams.length; i++) {
				Varnode input = nextParams[i];
				if(input.isConstant()) {
					SMLogger.log("      [%d] %s", i, Util.toSignedInt(input.getOffset()));
				} else if(input.isUnique()) {
					Varnode defnode = input.getDef().getInput(0);
					String text = getStringFromUnique(defnode.getAddress());
					
					if(text != null) {
						SMLogger.log("      [%d] string = \"%s\"", i, text);
					} else {
						SMLogger.log("      [%d] %s   addr = %s", i, input, defnode);
					}
				} else {
					SMLogger.log("      [%d] %s", i, input);
					
				}
			}
		}
		*/
	}
	
	public void close() {
		if(isClosed) return;
		isClosed = true;
		decomp.closeProgram();
	}
	
	private String getStringFromUnique(Varnode node) {
		if(node == null) return null;
		PcodeOp op = node.getDef();
		
		if(op == null || op.getNumInputs() < 1) return null;
		Varnode input = op.getInput(0);
		
		if(input == null) return null;
		return getStringFromUnique(input.getAddress());
	}
	
	private String getStringFromUnique(Address address) {
		Address addr = Util.getAddressFromLong(address.getOffset());
		if(!Util.isValidAddress(addr)) return null;
		
		if(addr.isMemoryAddress()) {
			return Util.readTerminatedString(addr);
		} else {
			return null;
		}
	}
}
