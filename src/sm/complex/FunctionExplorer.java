package sm.complex;

import java.io.Closeable;
import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import sm.SMFunctionObject;
import sm.util.LuaUtil;
import sm.util.Util;

import static sm.complex.SMStructure.TRACE;

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
	
	private boolean isClosed;
	
	private final DataType LUA_STATE_PTR;
	private DecompInterface decomp;
	public FunctionExplorer() {
		decomp = new DecompInterface();
		decomp.toggleCCode(false);
		decomp.openProgram(Util.getScript().getCurrentProgram());
		
		LUA_STATE_PTR = Util.getScript().getCurrentProgram().getDataTypeManager().getDataType("/lua.h/lua_State *");
	}
	
	public FuzzedFunction evaluate(SMFunctionObject object) {
		if(isClosed) return null;
		
		FuzzedFunction fuzzed = new FuzzedFunction();
		
		DecompileResults result = decomp.decompileFunction(object.getFunction(), 10, Util.getMonitor());
		HighFunction hfunc = result.getHighFunction();
		if(hfunc == null) throw new NullPointerException("The generated HighFunction was null ! Error: " + result.getErrorMessage());
		
		loadEverything(fuzzed, hfunc, object);
		object.setFuzzedFunction(fuzzed);
		
		return fuzzed;
	}
	
	public void close() {
		if(isClosed) return;
		isClosed = true;
		decomp.closeProgram();
	}
	
	protected void loadEverything(FuzzedFunction fuzzed, HighFunction set, SMFunctionObject object) {
		Instruction inst = Util.getInstructionBefore(set.getFunction().getEntryPoint());
		
		// TODO: Check for "sm.gui.createWidget has been removed" messages
		
		{
			Function function = set.getFunction();
			
			String name = "_" + object.getName() + "_" + function.getEntryPoint();
			if(!function.getName().equals(name)) {
				try {
					function.setName(name, SourceType.ANALYSIS);
				} catch(DuplicateNameException e) {
					e.printStackTrace();
				} catch(InvalidInputException e) {
					e.printStackTrace();
				}
			}
			
			Parameter[] params = function.getParameters();
			
			if(params.length > 0) {
				Parameter current = params[0];
				if(!current.getDataType().equals(LUA_STATE_PTR)) {
					try {
						current.setDataType(LUA_STATE_PTR, SourceType.ANALYSIS);
					} catch(InvalidInputException e) {
						e.printStackTrace();
					}
				}
			}
		}
		
		boolean firstCall = true;
		
		do {
			inst = inst.getNext();
			if(!Util.isInside(inst, set)) break;
			Address addr = inst.getAddress();
			
			String mnemonic = inst.getMnemonicString();
			
			if(CALL.equals(mnemonic)) {
				Iterator<PcodeOpAST> iter = set.getPcodeOps(addr);
				if(!iter.hasNext()) continue;
				
				PcodeOpAST ast = iter.next();
				Varnode node = ast.getInput(0);
				Address call_addr = node.getAddress();
				
				if(LuaUtil.isLuaFunctionPointer(call_addr)) {
					firstCall = false;
					
					String function = LuaUtil.getNameFromPointerAddress(call_addr);
					if(TRACE) {
						System.out.println(addr + ", " + function);
					}
					
					processCommand(fuzzed, function, inst, ast);
				} else {
					if(firstCall) {
						firstCall = false;
						if(TRACE) {
							System.out.println(addr + ", " + inst);
							System.out.printf("        : Calling Function: %s\n", node, call_addr);
							System.out.println();
						}
						
						enterFunction(fuzzed, call_addr, object, getCallParams(ast.getInputs()));
						continue;
					}
					
					for(int i = 1; i < ast.getNumInputs(); i++) {
						Varnode arg = ast.getInput(i);
						Address aaa = arg.getAddress();
						if(aaa.isStackAddress()) {
							// Check that the address points to Stack[0x4]
							
							if(aaa.getOffset() == 4) {
								if(TRACE) {
									System.out.println(addr + ", " + inst);
									System.out.printf("        : Calling Function: %s\n", node, call_addr);
									System.out.printf("        : [%d] %s   %d\n", i, arg, aaa.getOffset());
									System.out.println();
								}
								
								enterFunction(fuzzed, call_addr, object, getCallParams(ast.getInputs()));
								break;
							}
							
							// break;
						}
					}
				}
			}
		} while(inst != null);
		
		if(TRACE) {
			System.out.println();
			System.out.println();
			System.out.println();
		}
	}
	
	private Varnode[] getCallParams(Varnode[] inputs) {
		if(inputs.length == 0) return inputs;
		
		Varnode[] result = new Varnode[inputs.length - 1];
		for(int i = 1; i < inputs.length; i++) {
			result[i - 1] = inputs[i];
		}
		
		return result;
	}

	protected void enterFunction(FuzzedFunction fuzzed, Address func, SMFunctionObject object, Varnode... params) {
		enterFunction(fuzzed, func, object, 2, params);
	}
	
	protected void enterFunction(FuzzedFunction fuzzed, Address func, SMFunctionObject object, int depth, Varnode... params) {
		Function function = Util.getFunctionAt(func);
		if(function == null) return;
		
		DecompileResults result = decomp.decompileFunction(function, 10, Util.getMonitor());
		HighFunction hfunc = result.getHighFunction();
		if(hfunc == null) throw new NullPointerException("The generated HighFunction was null ! Error: " + result.getErrorMessage());
		
		traverseFunction(fuzzed, hfunc, object, depth, params);
	}
	
	@Deprecated
	protected void traverseFunction(FuzzedFunction fuzzed, HighFunction set, SMFunctionObject object, int depth, Varnode... params) {
		Instruction inst = Util.getInstructionBefore(set.getFunction().getEntryPoint());
		
		boolean firstCall = true;
		
		do {
			inst = inst.getNext();
			if(!Util.isInside(inst, set)) break;
			Address addr = inst.getAddress();
			
			String mnemonic = inst.getMnemonicString();
			
			if(CALL.equals(mnemonic)) {
				if(TRACE) {
					System.out.println("        " + addr + ", " + inst);
				}
				
				Iterator<PcodeOpAST> iter = set.getPcodeOps(addr);
				if(!iter.hasNext()) continue;
				
				PcodeOpAST ast = iter.next();
				Varnode node = ast.getInput(0);
				Address call_addr = node.getAddress();
				
				if(TRACE) {
					System.out.println("        node    : " + node);
				}
				
				if(LuaUtil.isLuaFunctionPointer(call_addr)) {
					firstCall = false;
					
					String function = LuaUtil.getNameFromPointerAddress(call_addr);
					if(TRACE) {
						System.out.println("        found   : " + function);
					}
					
					processCommand(fuzzed, function, inst, ast, set.getFunction().getParameters(), params);
				} else {
					if(depth > 0) {
						if(firstCall) {
							firstCall = false;
							if(TRACE) {
								System.out.println(addr + ", " + inst);
								System.out.printf("        : Calling Function: %s\n", node, call_addr);
								System.out.println();
							}
							
							enterFunction(fuzzed, call_addr, object, depth - 1, getCallParams(ast.getInputs()));
							continue;
						}
						
						for(int i = 1; i < ast.getNumInputs(); i++) {
							Varnode arg = ast.getInput(i);
							Address aaa = arg.getAddress();
							if(aaa.isStackAddress()) {
								// Check that the address points to Stack[0x4]
								
								if(aaa.getOffset() == 4) {
									if(TRACE) {
										System.out.println(addr + ", " + inst);
										System.out.printf("        : Calling Function: %s\n", node, call_addr);
										System.out.printf("        : [%d] %s   %d\n", i, arg, aaa.getOffset());
										System.out.println();
									}
									
									enterFunction(fuzzed, call_addr, object, depth - 1, getCallParams(ast.getInputs()));
									break;
								}
								
								// break;
							}
						}
					}
				}
			}
		} while(inst != null);
	}
	
	private Varnode[] computeValues(PcodeOpAST command, Parameter[] functionParams, Varnode[] callParams) {
		if(functionParams == null || callParams == null) return command.getInputs();
		
		
		// If value is a register then get the def
		Varnode[] result = new Varnode[command.getNumInputs()];
		for(int i = 1; i < command.getNumInputs(); i++) {
			Varnode input = command.getInput(i);
			
			if(input.isRegister()) {
				HighVariable hv = input.getHigh();
				VariableStorage vs = hv.getStorage();
				
				String varName = hv.getName();
				if(varName != null) {
					// TODO: !!!! Check for all asignments of that register!!!!!
					
					if(TRACE) {
						System.out.println("              Op: " + input + "  name = " + hv.getName() + "   register = " + vs);
					}
					
					for(int j = 0; j < functionParams.length; j++) {
						Parameter param = functionParams[j];
						if(param.getName().equals(varName)) {
							if(j >= callParams.length) break;
							result[i] = callParams[j];
							
							break;
						}
					}
				}
			} else {
				Address addr = input.getAddress();
				if(addr.isStackAddress()) {
					for(int j = 0; j < functionParams.length; j++) {
						Parameter param = functionParams[j];
						if(param.isStackVariable()) {
							if(param.getStackOffset() == addr.getOffset()) {
								if(j >= callParams.length) break;
								result[i] = callParams[j];
								
								break;
							}
						}
					}
				}
			}
			
			if(result[i] == null) result[i] = input;
		}
		
		return result;
	}
	
	private void processCommand(FuzzedFunction fuzzed, String name, Instruction instruction, PcodeOpAST command) {
		processCommand(fuzzed, name, instruction, command, null, null);
	}
	
	private void processCommand(FuzzedFunction fuzzed, String name, Instruction instruction, PcodeOpAST command, Parameter[] functionParams, Varnode[] callParams) {
		Varnode[] computed = computeValues(command, functionParams, callParams);
		
		// TODO: If "luaL_checklstring" is input for "lua_pushfstring" then it is not an argument!
		// lua_pushfstring(param_1,"%s expected, got %s","number",extramsg);
		
		switch(name) {
			case "luaL_checkudata": {
				if(computed.length < 4) break;
				
				long index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				String str = getStringFromUnique(Util.getPcodeVarnode(computed, 3, 0).getAddress());
				if(TRACE) System.out.printf("  luaL_checkudata(lua_State, %d, \"%s\");\n", index, str);
				
				fuzzed.setArgument(index, str);
				break;
			}
			case "luaL_checktype": {
				if(computed.length < 4) break;
				
				long index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				long type = Util.toSignedInt(Util.getPcodeVarnode(computed, 3).getOffset());
				if(TRACE) System.out.printf("  luaL_checktype(lua_State, index = %d, type = %d);\n", index, type);
				
				fuzzed.setArgument(index, LuaUtil.getTypeNameFromId(type));
				return;
			}
			case "luaL_checklstring": {
				if(computed.length < 3) break;
				
				int index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				if(TRACE) System.out.printf("  luaL_checklstring(lua_State, index = %d, ret = ???);\n", index, index);
				
				fuzzed.setArgument(index, "string");
				return;
			}
			case "luaL_checkinteger": {
				if(computed.length < 3) break;
				
				int index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				
				fuzzed.setArgument(index, "number");
				return;
			}
			case "lua_isnumber": {
				if(computed.length < 3) break;
				
				int index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				
				fuzzed.setArgument(index, "number");
				return;
			}
			case "lua_getmetatable": {
				if(computed.length < 3) break;
				//int index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				
				// TODO: maybe more aproperiate "userdata"?????
				//fuzzed.setArgument(index, "table");
				return;
			}
			case "lua_getfield": {
				if(computed.length < 4) break;
				
				long index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				String str = getStringFromUnique(Util.getPcodeVarnode(computed, 3, 0).getAddress());
				if(TRACE) System.out.printf("  lua_getfield(lua_State, index = %d, \"%s\");\n", index, str);
				
				fuzzed.setArgument(index, str);
				return;
			}
			case "lua_type": {
				if(computed.length < 3) break;
				
				long index = Util.toSignedInt(computed[2].getOffset());
				if(TRACE) System.out.printf("  lua_type(lua_State, %d);\n", index);
				
				return;
			}
			case "luaL_error": {
				if(computed.length < 4) break;
				
				String str = getStringFromUnique(Util.getPcodeVarnode(computed, 2, 0).getAddress());
				if(TRACE) System.out.printf("  luaL_error(lua_State, \"%s\");\n", str);
				
				if(str != null) {
					if(str.startsWith("Expected %d arguments")) {
						int args = Util.toSignedInt(computed[3].getOffset());
						fuzzed.minimumArguments = args;
						fuzzed.maximumArguments = args;
					} else if(str.startsWith("Expected at most %d arguments")) {
						int args = Util.toSignedInt(computed[3].getOffset());
						fuzzed.maximumArguments = args;
					} else if(str.startsWith("Expected at least %d arguments")) {
						int args = Util.toSignedInt(computed[3].getOffset());
						fuzzed.minimumArguments = args;
					} else {
						fuzzed.errors.add(str);
					}
				}
				
				break;
			}
			
			case "lua_topointer": return;
			case "lua_gettop": return; // TODO: This function gets the amount of arguments on the stack
			
			default: {
				// Do nothing
			}
		}
		
		if(TRACE) {
			for(int i = 1; i < computed.length; i++) {
				Varnode input = computed[i];
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
