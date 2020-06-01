package sm.complex;

import static sm.complex.SMStructure.*;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.help.UnsupportedOperationException;

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
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
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
@Deprecated(forRemoval = true)
public class FunctionExplorer2 implements Closeable {
	private static final String CALL = "CALL";
	private static final int MAX_DEPTH = 4;
	
	private boolean isClosed;
	
	private final DataType LUA_STATE_PTR;
	private DecompInterface decomp;
	public FunctionExplorer2() {
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
		/*{
			Function function = object.getFunction();
			Parameter[] params = function.getParameters();
			Varnode[] varnodes = new Varnode[params.length];
			
			System.out.println("Parameters:");
			for(int i = 0; i < params.length; i++) {
				Parameter param = params[i];
				if(!param.getDataType().equals(LUA_STATE_PTR)) {
					try {
						param.setDataType(LUA_STATE_PTR, SourceType.ANALYSIS);
					} catch(InvalidInputException e) {
						e.printStackTrace();
					}
				}
				
				varnodes[i] = param.getFirstStorageVarnode();
				System.out.printf("    [%d]: %s\n", i, varnodes[i]);
			}
			System.out.println();
			
			enterFunctionStart(fuzzed, object, varnodes);
			if(true) return;
		}
		
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
		*/
		

		// TODO: Check for "sm.gui.createWidget has been removed" messages
		
		List<Instruction> instructions = getCallInstructions(set);
		
		for(int instIndex = 0; instIndex < instructions.size(); instIndex++) {
			Instruction inst = instructions.get(instIndex);
			Address instAddress = inst.getAddress();
			
			// TODO: What else can you get from this iterator?
			Iterator<PcodeOpAST> iter = set.getPcodeOps(instAddress);
			if(!iter.hasNext()) continue;
			
			PcodeOpAST command = iter.next();
			Address callAddress = command.getInput(0).getAddress();
			
			if(LuaUtil.isLuaFunctionPointer(callAddress)) {
				
				String function = LuaUtil.getNameFromPointerAddress(callAddress);
				if(TRACE) System.out.printf("%s, CALL LUA51::%s\n", instAddress, function);
				
				//processCommand(fuzzed, function, inst, command, set.getFunction().getParameters(), params);
			} else {
				// If this is set, the function will compute values downwards.
				boolean traverse = false;
				
				if(instIndex == 0) {
					if(TRACE) {
						System.out.printf("        : %s, %s\n", instAddress, inst);
						System.out.printf("            : Calling Function: %s\n", command.getInput(0), callAddress);
						System.out.println();
					}
					
					//enterFunction(fuzzed, call_addr, object, depth + 1, getCallParams(ast.getInputs()));
					traverse = true;
				}
				
				for(int i = 1; i < command.getNumInputs(); i++) {
					Varnode node = command.getInput(i);
					Address addr = node.getAddress();
					
					// This only works if we are at depth == 0
					// TODO: Generalize this check for all depths!
					if(addr.isStackAddress() && addr.getOffset() == 4) {
						traverse = true;
					}
				}
				
				
				
				if(traverse) {
					// TODO: Check if the function call uses the function parameter lua_State*
					// TODO: Only values that are known should be passed as parameters
					
					System.out.printf("%s, %s\n", instAddress, inst);
					for(int i = 1; i < command.getNumInputs(); i++) {
						Varnode node = command.getInput(i);
						System.out.printf("        args[%d]: %s\n", i, node);
					}
					System.out.println();
					
					enterFunctionNew(fuzzed, set, callAddress, 0, null);
				}
			}
		}
	}
	
	// TODO: Check if there is an easier way to pass the depth value.
	private void enterFunctionNew(FuzzedFunction fuzzed, HighFunction parent, Address callAddress, int depth, Varnode[] params) {
		Function function = Util.getFunctionAt(callAddress);
		if(function == null) return;
		
		DecompileResults result = decomp.decompileFunction(function, 10, Util.getMonitor());
		HighFunction local = result.getHighFunction();
		if(local == null) {
			throw new NullPointerException("The generated HighFunction was null ! Error: " + result.getErrorMessage());
		}
		
		traverseFunctionNew(fuzzed, parent, local, depth, params);
	}
	
	private void traverseFunctionNew(FuzzedFunction fuzzed, HighFunction parent, HighFunction local, int depth, Varnode[] params) {
		List<Instruction> instructions = getCallInstructions(local);
		
		for(int instIndex = 0; instIndex < instructions.size(); instIndex++) {
			Instruction inst = instructions.get(instIndex);
			Address instAddress = inst.getAddress();
			
			// TODO: What else can you get from this iterator?
			Iterator<PcodeOpAST> iter = local.getPcodeOps(instAddress);
			if(!iter.hasNext()) continue;
			
			PcodeOpAST command = iter.next();
			Address callAddress = command.getInput(0).getAddress();
			
			if(LuaUtil.isLuaFunctionPointer(callAddress)) {
				
				String function = LuaUtil.getNameFromPointerAddress(callAddress);
				if(TRACE) System.out.printf("%s, CALL LUA51::%s\n", instAddress, function);
				
				//processCommand(fuzzed, function, inst, command, set.getFunction().getParameters(), params);
			} else {
				// If this is set, the function will compute values downwards.
				boolean traverse = false;
				
				if(instIndex == 0) {
					if(TRACE) {
						System.out.printf("        : %s, %s\n", instAddress, inst);
						System.out.printf("            : Calling Function: %s\n", command.getInput(0), callAddress);
						System.out.println();
					}
					
					//enterFunction(fuzzed, call_addr, object, depth + 1, getCallParams(ast.getInputs()));
					traverse = true;
				}
				
				for(int i = 1; i < command.getNumInputs(); i++) {
					Varnode node = command.getInput(i);
					Address addr = node.getAddress();
					
					// This only works if we are at depth == 0
					// TODO: Generalize this check for all depths!
					if(addr.isStackAddress() && addr.getOffset() == 4) {
						traverse = true;
					}
				}
				
				
				
				if(traverse) {
					// TODO: Check if the function call uses the function parameter lua_State*
					// TODO: Only values that are known should be passed as parameters
					
					System.out.printf("%s, %s\n", instAddress, inst);
					for(int i = 1; i < command.getNumInputs(); i++) {
						Varnode node = command.getInput(i);
						System.out.printf("        args[%d]: %s\n", i, node);
					}
					System.out.println();
					
					//enterFunctionNew(fuzzed, local, callAddress, 0, null);
				}
			}
		}
	}
	
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
	
	private Varnode[] resolveParams(Varnode[] inputs, Parameter[] params) {
		if(inputs.length == 0) return new Varnode[0];
		
		Varnode[] result = new Varnode[inputs.length - 1];
		for(int i = 1; i < inputs.length; i++) {
			result[i - 1] = inputs[i];
		}
		
		return result;
	}
	
	@Deprecated(forRemoval = true)
	private Varnode[] getCallParams(Varnode[] inputs) {
		if(inputs.length == 0) return inputs;
		
		Varnode[] result = new Varnode[inputs.length - 1];
		for(int i = 1; i < inputs.length; i++) {
			result[i - 1] = inputs[i];
		}
		
		return result;
	}
	
	protected void enterFunctionStart(FuzzedFunction fuzzed, SMFunctionObject object, Varnode... params) {
		enterFunction(fuzzed, object.getFunction().getEntryPoint(), 0, params);
	}
	
	protected void enterFunction(FuzzedFunction fuzzed, Address func, int depth, Varnode... params) {
		Function function = Util.getFunctionAt(func);
		
		if(function == null) return;
		
		DecompileResults result = decomp.decompileFunction(function, 10, Util.getMonitor());
		HighFunction hfunc = result.getHighFunction();
		if(hfunc == null) throw new NullPointerException("The generated HighFunction was null ! Error: " + result.getErrorMessage());
		
		traverseFunction(fuzzed, hfunc, depth, params);
	}
	
	@Deprecated
	protected void traverseFunction(FuzzedFunction fuzzed, HighFunction set, int depth, Varnode... params) {
		Instruction inst = Util.getInstructionBefore(set.getFunction().getEntryPoint());
		
		// TODO: Read input's and print outputs!
		// The function arguments should change to the correct type when it's identified that it should have another type!
		
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
				
				if(TRACE) {
					System.out.println(addr + ", " + inst);
				}
				
				if(LuaUtil.isLuaFunctionPointer(call_addr)) {
					firstCall = false;
					
					String function = LuaUtil.getNameFromPointerAddress(call_addr);
					if(TRACE) {
						System.out.println("        FOUND -> LUA51::" + function);
					}
					
					processCommand(fuzzed, function, inst, ast, set.getFunction().getParameters(), params);
				} else if(depth < MAX_DEPTH) {
					/*Parameter[] c_params = set.getFunction().getParameters();
					Parameter lua_ptr = null;
					for(int i = 0; i < c_params.length; i++) {
						Parameter prm = c_params[i];
						System.out.println("        ptr: i=" + i + "  " + prm);
						if(prm.getDataType().equals(LUA_STATE_PTR)) {
							lua_ptr = prm;
							//System.out.println("        ptr: offset = " + lua_ptr);
							break;
						}
					}
					
					Varnode[] computed = computeValues(ast, set.getFunction().getParameters(), params);
					*/
					//resolveInput(computed, set.getFunction().getParameters());
					
					// TODO: Instead of a loop. Just check if the computer values point to params
					// TODO: callParams should only be used when checking with Function.getParameters()!!!
					boolean shouldTraverse = false;
					for(int i = 1; i < ast.getNumInputs(); i++) {
						Varnode arg = ast.getInput(i);
						Address adr = arg.getAddress();
						System.out.println("        arg: i=" + i + "  " + arg);
						
						if(depth == 0) {
							// This will only work for the first level of functions
							if(adr.isStackAddress() && adr.getOffset() == 4) {
								shouldTraverse = true;
							}
						} else {
							HighVariable hva = arg.getHigh();
							System.out.println("          high: i=" + i + "  " + hva.getStorage());
							System.out.println("          high: i=" + i + "  " + hva.getName());
							
							PcodeOp aop = arg.getDef();
							if(aop != null && aop.getNumInputs() > 0) {
								System.out.println("          op: " + aop);
								Varnode ainp = aop.getInput(0);
								System.out.println("          op: " + ainp);
								System.out.println("          op: " + ainp.getDef());
								System.out.println("          op: " + ainp.getAddress());
								System.out.println("          op: " + ainp.getHigh().getName());
								
							}
						}
					}
					
					/*
					System.out.println("Trying to change the function argument " + i + ", " + "???");
					Function call_function = Util.getFunctionAt(call_addr);
					Parameter[] call_params = call_function.getParameters();
					if(call_params.length > i - 1) {
						Parameter call_param = call_params[i - 1];
						System.out.println("Param: " + call_param);
						
						if(!call_param.getDataType().equals(LUA_STATE_PTR)) {
							try {
								call_param.setDataType(LUA_STATE_PTR, SourceType.ANALYSIS);
							} catch(InvalidInputException e) {
								e.printStackTrace();
							}
						}
					}
					*/
					
					

					System.out.println("        Traverse: " + shouldTraverse);
					if(depth == 0) System.out.println("------------------------------------------------------");
					
					if(inst.getAddress().toString().equals("006de05f")) {
						/*
						for(int k = 0; k < params.length; k++) {
							System.out.printf("            params[%d]: %s\n", k, params[k]);
						}
						System.out.println();
						*/
						enterFunction(fuzzed, call_addr, depth + 1, getCallParams(ast.getInputs()));
					}
					
					/*
					for(int i = 1; i < computed.length; i++) {
						Varnode arg = computed[i];
						
						Address aaa = arg.getAddress();
						System.out.println("        args: i=" + i + "  " + arg);
						
						if(lua_ptr == null) continue;
						
						//if((aaa.isStackAddress() && lua_ptr.isStackVariable() && (aaa.getOffset() == lua_ptr.getStackOffset()))
						//|| (aaa.isRegisterAddress() && lua_ptr.isRegisterVariable() && (aaa.equals(lua_ptr.getRegister().getAddress())))) {
						// TODO: This is not always true
						// Check that the address points to Stack[0x4]
						
						boolean testing = false;
						if(depth > 0) {
							HighVariable avh = arg.getHigh();
							if(avh != null) {
								for(int j = 0; j < c_params.length; i++) {
									Parameter prm = c_params[i];
									System.out.println("        FOUND: i=" + i + "  " + prm);
									if(prm.getDataType().equals(LUA_STATE_PTR)) {
										testing = true;
										System.out.println("        FOUND: offset = " + lua_ptr);
										break;
									}
								}
							}
						}
						if((depth == 0 && aaa.isStackAddress() && aaa.getOffset() == 4)
						|| (testing)) {
							
							firstCall = false;
							
							if(TRACE) {
								System.out.println("        " + addr + ", " + inst);
								System.out.printf("        : Calling Function: %s\n", node, call_addr);
								System.out.printf("        : [%d] %s   %d\n", i, arg, aaa.getOffset());
								System.out.println();
							}
							
							// Change tye new functions call datatype to lua_State
							
							if(depth == 0) {
								System.out.println("Trying to change the function argument " + i + ", " + "???");
								
								Function call_function = Util.getFunctionAt(call_addr);
								Parameter[] call_params = call_function.getParameters();
								if(call_params.length > i - 1) {
									Parameter call_param = call_params[i - 1];
									System.out.println("Param: " + call_param);
									
									/*if(!call_param.getDataType().equals(LUA_STATE_PTR)) {
										try {
											call_param.setDataType(LUA_STATE_PTR, SourceType.ANALYSIS);
										} catch(InvalidInputException e) {
											e.printStackTrace();
										}
									}*
								}
							}
							
							if(inst.getAddress().toString().equals("006de05f") || depth > 0) {
								for(int k = 0; k < params.length; k++) {
									System.out.printf("            params[%d]: %s\n", k, params[k]);
								}
								for(int k = 0; k < computed.length; k++) {
									System.out.printf("            computed[%d]: %s\n", k, computed[k]);
								}
								System.out.println();
								enterFunction(fuzzed, call_addr, object, depth + 1, getCallParams(computed));
							}
							
							break;
						}
					}*/
					
					if(firstCall) {
						firstCall = false;
						if(TRACE) {
							System.out.println("        " + addr + ", " + inst);
							System.out.printf("        : Calling Function: %s\n", node, call_addr);
							System.out.println();
						}
						
						//enterFunction(fuzzed, call_addr, object, depth + 1, getCallParams(ast.getInputs()));
						continue;
					}
				}
			}
		} while(inst != null);
	}
	
	private Varnode[] computeParams(PcodeOpAST command, Parameter[] functionParams, Varnode[] callParams) {
		Varnode[] result = new Varnode[command.getNumInputs()];
		
		return result;
	}
	
	// TODO: Show where the lua_State* object is inside the callParams
	// TODO: Object callParams
	private Varnode[] computeValues(PcodeOpAST command, Parameter[] functionParams, Varnode[] callParams) {
		if(functionParams == null) return command.getInputs();
		
		// If value is a register then get the def
		Varnode[] result = new Varnode[command.getNumInputs()];
		for(int i = 1; i < command.getNumInputs(); i++) {
			Varnode input = command.getInput(i);
			if(result[i] == null) result[i] = input;
			if(TRACE) System.out.printf("                compute: [%d] -> %s\n", i, result[i]);
			
			PcodeOp op = input.getDef();
			if(op != null) {
				Varnode testNode = op.getInput(0);
				Address addr = testNode.getAddress();
				
				if(TRACE) {
					System.out.println("                    inp = " + input);
					System.out.println("                    op = " + op);
					System.out.println("                    node = " + testNode);
					System.out.println("                    addr = " + addr);
				}
				
				if(addr.isStackAddress()) {
					for(int j = 0; j < functionParams.length; j++) {
						Parameter param = functionParams[j];
						if(param.isStackVariable()) {
							//System.out.println(j + ", param = " + param);
							if(param.getStackOffset() == addr.getOffset()) {
								if(j >= callParams.length) break;
								
								if(TRACE) System.out.println("                    Found: " + result[i]);
								result[i] = callParams[j];
								//.getVariableStorage().getFirstVarnode();
								if(TRACE) System.out.println("                        " + i + " -> " + result[i]);
								break;
							}
						}
					}
				}
			}
			
			if(input.isRegister()) {
				HighVariable hv = input.getHigh();
				VariableStorage vs = hv.getStorage();
				
				String varName = hv.getName();
				if(varName != null) {
					// TODO: !!!! Check for all asignments of that register!!!!!
					
					if(TRACE) {
						System.out.println("              Op: " + input + "  name = " + hv.getName() + "   register = " + vs);
						Varnode first = vs.getFirstVarnode();
						
						System.out.println("              fr: " + first);
						System.out.println("              idef: " + input.getDef());
						System.out.println("              fdef: " + first.getDef());
						System.out.println("              addr: " + first.getAddress());
						System.out.println("              offs: " + first.getOffset());
					}
					
					/*for(int j = 0; j < functionParams.length; j++) {
						Parameter param = functionParams[j];
						System.out.printf("              pram[%d]: %s\n", j, param);
						if(param.getName().equals(varName)) {
							if(j >= callParams.length) break;
							System.out.printf("              ----->[%d]: %s\n", j, param);
							System.out.println("              " + param.getVariableStorage().getFirstVarnode());
							//result[i] = callParams[j];
							
							break;
						}
					}*/
				}
			} else {
				Address addr = input.getAddress();
				if(addr.isStackAddress()) {
					for(int j = 0; j < functionParams.length; j++) {
						Parameter param = functionParams[j];
						if(param.isStackVariable()) {
							if(param.getStackOffset() == addr.getOffset()) {
								if(j >= callParams.length) break;
								if(TRACE) System.out.println("                    Found: " + result[i]);
								result[i] = callParams[j];
								if(TRACE) System.out.println("                        " + i + " -> " + result[i]);
								
								break;
							}
						}
					}
				}
			}
		}
		
		for(int i = 1; i < result.length; i++) {
			Varnode node = result[i];
			Address addr = node.getAddress();
			
			HighVariable var = node.getHigh();
			if(var == null) continue;
			String name = var.getName();
			System.out.println("Test: " + var.getName());
			
			for(int j = 0; j < functionParams.length; j++) {
				Parameter param = functionParams[j];
				if(param.getName().equals(name)) {
					if(TRACE) System.out.println("                    j=" + j + ": " + callParams[j]);
					if(TRACE) System.out.println("                  - j=" + j + ": " + functionParams[j]);
					//if(j >= callParams.length) break;
					if(TRACE) System.out.println("                    Found: " + result[i]);
					result[i] = callParams[j];
					if(TRACE) System.out.println("                        " + i + " -> " + result[i]);
					
					break;
				}
			}
		}
		
		
		if(TRACE) {
			System.out.println();
			for(int i = 1; i < result.length; i++) {
				System.out.printf("                result : [%d] -> %s\n", i, result[i]);
			}
		}
		
		return result;
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
			case "luaL_checklstring": { // Not always true !
				/*
				if(computed.length < 3) break;
				
				int index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				if(TRACE) System.out.printf("  luaL_checklstring(lua_State, index = %d, ret = ???);\n", index, index);
				
				fuzzed.setArgument(index, "string");
				*/
				return;
			}
			case "luaL_checkinteger": {
				if(computed.length < 3) break;
				int index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				fuzzed.setArgument(index, "number");
				return;
			}
			case "luaL_checknumber": {
				if(computed.length < 3) break;
				int index = Util.toSignedInt(Util.getPcodeVarnode(computed, 2).getOffset());
				fuzzed.setArgument(index, "number");
				return;
			}
			case "lua_isnumber": { // TODO: ????
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
				//if(computed.length < 3) break;
				
				//long index = Util.toSignedInt(computed[2].getOffset());
				//if(TRACE) System.out.printf("  lua_type(lua_State, %d);\n", index);
				
				return;
			}
			case "lua_pushfstring": {
				if(computed.length < 4) break;
				
				String str = getStringFromUnique(Util.getPcodeVarnode(computed, 2, 0).getAddress());
				if(TRACE) System.out.printf("  lua_pushfstring(lua_State, \"%s\");\n", str);
				
				break;
			}
			case "luaL_argerror": {
				if(computed.length < 4) break;
				
				checkArgError(fuzzed, command, functionParams, computed);
				
				
				break;
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
			
			case "lua_typename": return;
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

	private void checkArgError(FuzzedFunction fuzzed, PcodeOpAST command, Parameter[] functionParams, Varnode[] computed) {
		Varnode last = computed[3];
		if(!last.isRegister()) return;
		
		PcodeOp op = last.getDef();
		
		if(op == null || !op.getMnemonic().equals(CALL)) return;
		
		Varnode addr = op.getInput(0);
		//System.out.println("      : " + last);
		//System.out.println("          : " + op);
		//System.out.println("          : addr = " + addr);
		
		Address call_addr = addr.getAddress();
		if(!LuaUtil.isLuaFunctionPointer(call_addr)) return;
		
		String function = LuaUtil.getNameFromPointerAddress(call_addr);
		if(!function.equals("lua_pushfstring")) return;
		
		if(op.getNumInputs() < 3) return;
		String msg = getStringFromUnique(Util.getPcodeVarnode(op.getInputs(), 2, 0).getAddress());
		String type = getStringFromUnique(Util.getPcodeVarnode(op.getInputs(), 3, 0).getAddress());
		
		
		if(msg.equals("%s expected, got %s")) {
			//System.out.println("            1: " + op.getInput(1));
			System.out.println("            type: " + type);
			System.out.println("            num: " + computed[2].getOffset());
			long index = computed[2].getOffset();
			
			fuzzed.setArgument(index, type);
		}
		/*
		if(TRACE) {
			System.out.println("        FOUND -> LUA51::" + function);
			
			for(int i = 1; i < op.getNumInputs(); i++) {
				Varnode input = op.getInput(i);
				System.out.printf("      [%d] %s\n", i, input);
			}
		}
		*/
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
