package sm.complex;

import static sm.complex.SMStructure.*;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import sm.SMFunctionObject;
import sm.util.LuaUtil;
import sm.util.Util;

/**
 * This class will search throuh a decompiled function and try guess the 
 * structure of how it is made.
 * 
 * This is structure is really compilcated and is not easy to find.
 * 
 * 
 * @author HardCoded
 */
public class FunctionExplorer implements Closeable {
	private static final String CALL = "CALL";
	private static final String COPY = "COPY";
	private static final int MAX_DEPTH = 3;
	
	private boolean isClosed;
	
	private final DataType LUA_STATE_PTR;
	private DecompInterface decomp;
	public FunctionExplorer() {
		decomp = new DecompInterface();
		decomp.toggleCCode(false);
		decomp.openProgram(Util.getScript().getCurrentProgram());
		
		LUA_STATE_PTR = Util.getDataTypeManager().getDataType("/lua.h/lua_State *");
	}
	
	public FuzzedFunction evaluate(SMFunctionObject object) {
		if(isClosed) return null;
		
		FuzzedFunction fuzzed = new FuzzedFunction();
		Function function = object.getFunction();
		
		Varnode[] varnode = new Varnode[1];
		{
			Parameter[] params = function.getParameters();
			
			// TODO: Should the function names be resolved????
			// TODO: What do we do if this fails?
			if(params.length > 0) {
				// Because this is the first function in the evaluation tree
				// this parameter should be a lua_State*
				Parameter param = params[0];
				
				varnode[0] = param.getFirstStorageVarnode();
				
				if(!param.getDataType().equals(LUA_STATE_PTR)) {
					try {
						param.setDataType(LUA_STATE_PTR, SourceType.ANALYSIS);
					} catch(InvalidInputException e) {
						e.printStackTrace();
					}
				}
			}
		}
		
		enterFunction(fuzzed, function.getEntryPoint(), 0, varnode);
		object.setFuzzedFunction(fuzzed);
		
		return fuzzed;
	}
	
	private void enterFunction(FuzzedFunction fuzzed, Address callAddress, int depth, Varnode[] params) {
		if(Util.isMonitorCancelled()) return;
		
		Function function = Util.getFunctionAt(callAddress);
		if(function == null) return;
		
		DecompileResults result = decomp.decompileFunction(function, SMStructure.DECOMPILE_TIMEOUT, null);
		HighFunction local = result.getHighFunction();
		if(local == null) {
			/* This is usually the result of a TimeoutException or that the
			 * TaskMonitor was closed.
			 * 
			 * This is because some functions take more than 30 seconds to
			 * complete and they should probably be handled separatly.
			 */
			System.err.println("The generated HighFunction was null ! Error: " + result.getErrorMessage());
			return;
		}
		
		try {
			traverseFunction(fuzzed, local, depth, params);
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	private void traverseFunction(FuzzedFunction fuzzed, HighFunction local, int depth, Varnode[] params) {
		List<Instruction> instructions = getCallInstructions(local);
		
		for(int instIndex = 0; instIndex < instructions.size(); instIndex++) {
			Instruction inst = instructions.get(instIndex);
			Address instAddress = inst.getAddress();
			
			// TODO: What else can you get from this iterator?
			Iterator<PcodeOpAST> iter = local.getPcodeOps(instAddress);
			if(!iter.hasNext()) continue;
			
			PcodeOpAST command = iter.next();
			Address callAddress = command.getInput(0).getAddress();
			
			
			if(LuaUtil.isLuaPointer(callAddress)) {
				String function = LuaUtil.getNameFromPointer(callAddress);
				Varnode[] nextParams = resolveParams(command, local, params);
				
				if(TRACE) {
					System.out.printf("%s, CALL LUA51::%s\n", instAddress, function);
					
					for(int i = 0; i < nextParams.length; i++) {
						Varnode node = nextParams[i];
						System.out.printf("        args[%d]: %s\n", i, node);
					}
					System.out.println();
				}
				
				processCommand(fuzzed, function, command, nextParams);
			} else if(depth < MAX_DEPTH) {
				if(TRACE) {
					System.out.println("---------------------------------");
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
						System.out.printf("        : %s, %s\n", instAddress, inst);
						System.out.printf("            : Calling Function: %s\n", command.getInput(0), callAddress);
						System.out.println();
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
						
						// TODO: Some decompiled code does not work if the parameter is of the wrong type
						//       therefore the parameter needs to be changed to the correct type.
						//
						//       This is not easy because sometimes PcodeOp can smash together values in
						//       an unexpected way. These unexpected values should be discarded because
						//       of complexity.
						//
						Function nextFunction = Util.getFunctionAt(callAddress);
						
						// TODO: This is really unexpected
						if(nextFunction == null) break;
						
						Parameter[] nextFunctionParams = nextFunction.getParameters();
						if(nextFunctionParams.length > i) {
							Parameter param = nextFunctionParams[i];
							
							// TODO: This has a tendency to fail....
							if(!param.getDataType().equals(LUA_STATE_PTR)) {
								try {
									param.setDataType(LUA_STATE_PTR, SourceType.ANALYSIS);
								} catch(InvalidInputException e) {
									e.printStackTrace();
								}
							}
						}
					}
				}
				
				if(traverse) {
					// TODO: Only values that are known should be passed as parameters
					// TODO: Sometimes arguments are pushed into registers before being pushed to a
					//       call command. The task is to check if any of these registers point to
					//       the current functions parameters. And if so change that value into the
					//       last known parameter value. Otherwise it should be null.
					//
					if(TRACE) {
						System.out.printf("%s, %s\n", instAddress, inst);
						for(int i = 0; i < nextParams.length; i++) {
							Varnode node = nextParams[i];
							System.out.printf("        args[%d]: %s\n", i, node);
						}
						System.out.println();
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
			// System.out.printf("        input[%d]: %s\n", i, node);

			// TODO: This code is duplicated!
			HighVariable hv = node.getHigh();
			if(hv != null) {
				// System.out.printf("          storage: %s\n", hv.getStorage());
				// System.out.printf("          name: %s\n", hv.getName());
				
				for(int k = 0; k < Math.min(params.length, inputs.length); k++) {
					Parameter param = params[k];
					if(param.getName().equals(hv.getName())) {
						// System.out.printf("        RESULT[%d]: %s\t -> %s\n", k, param, inputs[k]);
						result[i - 1] = inputs[k];
						break;
					}
				}
			}
			
			// TODO: For how long do we need to traverse this????
			PcodeOp op = node.getDef();
			if(op != null && op.getNumInputs() > 0) {
				// System.out.printf("          op: %s\n", op);
				// System.out.printf("          op: %s\n", op.getInput(0));
				
				Varnode node_2 = op.getInput(0);
				if(node_2 != null) {
					HighVariable hv_2 = node_2.getHigh();
					if(hv_2 != null) {
						// TODO: This code is duplicated!
						// System.out.printf("            storage: %s\n", hv_2.getStorage());
						// System.out.printf("            name: %s\n", hv_2.getName());
						
						for(int k = 0; k < Math.min(params.length, inputs.length); k++) {
							Parameter param = params[k];
							
							if(param.getName().equals(hv_2.getName())) {
								// System.out.printf("        RESULT[%d]: %s\t -> %s\n", k, param, inputs[k]);
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
		System.out.println("       RESULTS:");
		for(int i = 0; i < result.length; i++) {
			Varnode node = result[i];
			System.out.printf("        result[%d]: %s\n", i, node);
		}
		System.out.println();
		*/
		
		return result;
	}
	
	/**
	 * @param set
	 * @return All the call instructions inside the given function.
	 */
	private List<Instruction> getCallInstructions(HighFunction set) {
		List<Instruction> list = new ArrayList<Instruction>();
		Instruction inst = Util.getInstructionBefore(set);
		
		while(inst != null) {
			if(!Util.isInside(inst, set)) break;
			
			if(CALL.equals(inst.getMnemonicString())) {
				list.add(inst);
			}
			
			inst = inst.getNext();
		}
		
		return list;
	}
	
	private boolean checkArgError(FuzzedFunction fuzzed, PcodeOpAST command, Varnode[] newParams) {
		if(newParams.length < 3) return false;
		
		//System.out.println("      : len = " + newParams.length);
		
		Varnode last = newParams[2];
		if(last == null || !last.isRegister()) return false;
		
		PcodeOp op = last.getDef();
		
		if(op == null || !op.getMnemonic().equals(CALL)) return false;
		
		Varnode addr = op.getInput(0);
		//System.out.println("      : " + last);
		//System.out.println("          : " + op);
		//System.out.println("          : addr = " + addr);
		
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
				System.out.println("            msg:  \"" + msg + "\"");
				System.out.println("            type: \"" + type + "\"");
				System.out.println("            num: " + newParams[1].getOffset());
			}
			long index = newParams[1].getOffset();
			
			fuzzed.setArgument(index, type);
			
			return true;
		}
		
		return false;
	}
	
	private boolean checkLuaError(FuzzedFunction fuzzed, PcodeOpAST command, Varnode[] newParams) {
		if(command.getNumInputs() < 4) return false;
		
		//System.out.println("Testing : " + command);
		
		//for(int i = 1; i < command.getNumInputs(); i++) {
		//Varnode input = command.getInput(i);
		//System.out.printf("        [%d]: %s\n", i, input);
		//}
		
		//System.out.println();
		
		PcodeOp[] msgCount = new PcodeOp[4];
		
		for(int i = 2; i < 4; i++) {
			Varnode input = command.getInput(i);
			//System.out.printf("        [%d]: %s\n", i, input);
			if(input == null) continue;
			
			HighVariable hv = input.getHigh();
			//System.out.printf("          high: %s\n", hv.getName());
			
			int count = 0;
			Varnode[] mem = hv.getInstances();
			for(int j = 0; j < mem.length; j++) {
				Varnode m = mem[j];
				PcodeOp op = m.getDef();
				if(op == null) continue;
				
				if(COPY.equals(op.getMnemonic())) {
					//System.out.printf("              [%d]: %s\n", j, op);
					msgCount[(i - 2) * 2 + (count++)] = op;
					if(count > 1) break;
				}
			}
			
			//System.out.println();
		}
		
		for(int i = 0; i < 4; i++) {
			if(msgCount[i] == null) return false;
			//System.out.printf("        [%d]: %s\n", i, msgCount[i]);
		}
		
		// Read message
		for(int i = 0; i < 2; i++) {
			String str = Util.readTerminatedString(Util.getAddressFromLong(msgCount[i].getInput(0).getOffset()));
			if(str == null) return false;
			
			int args = Util.toSignedInt(msgCount[i + 2].getInput(0).getOffset());
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
	
	private void processCommand(FuzzedFunction fuzzed, String name, PcodeOpAST command, Varnode[] nextParams) {
		switch(name) {
			case "luaL_checkudata": {
				if(nextParams.length < 3) break;
				long index = nextParams[1].getOffset();
				String str = getStringFromUnique(nextParams[2]);
				if(TRACE) {
					System.out.printf("  luaL_checkudata(lua_State, %d, \"%s\");\n", index, str);
				}
				
				fuzzed.setArgument(index, str);
				break;
			}
			case "luaL_checktype": {
				if(nextParams.length < 3) break;
				
				long index = Util.toSignedInt(Util.getPcodeVarnode(nextParams, 1).getOffset());
				long type = Util.toSignedInt(Util.getPcodeVarnode(nextParams, 2).getOffset());
				if(TRACE) {
					System.out.printf("  luaL_checktype(lua_State, index = %d, type = %d);\n", index, type);
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
					System.out.printf("  luaL_error(lua_State, \"%s\");\n", str);
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
			// TODO: Sometimes this gives false values
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
			
			// TODO: By using 'LuaUtil.getTypeNameFromId' this could be used to check what branches
			//       leads to a call to 'luaL_error'.
			case "lua_type": return;
			
			case "lua_getfield": return;
			case "lua_isnumber": return; // TODO: ???? 
			case "lua_getmetatable": return; // TODO: Sometimes this is used to create sub tables for returns and other stuff.
			case "lua_typename": return;
			case "lua_topointer": return;
			case "lua_gettop": return; // TODO: This function gets the amount of arguments on the stack
			
			default: {
				// Do nothing
			}
		}
		
		/*
		if(TRACE) {
			for(int i = 1; i < nextParams.length; i++) {
				Varnode input = nextParams[i];
				if(input.isConstant()) {
					System.out.printf("      [%d] %s\n", i, Util.toSignedInt(input.getOffset()));
				} else if(input.isUnique()) {
					Varnode defnode = input.getDef().getInput(0);
					String text = getStringFromUnique(defnode.getAddress());
					
					if(text != null) {
						System.out.printf("      [%d] string = \"%s\"\n", i, text);
					} else {
						System.out.printf("      [%d] %s   addr = %s\n", i, input, defnode);
					}
				} else {
					System.out.printf("      [%d] %s\n", i, input);
					
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
