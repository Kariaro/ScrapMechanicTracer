package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeAnalyser.NodeFunction;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeAnalyser.TracedFunction;
import sm.hardcoded.plugin.tracer.LuaTypeManager.Type;

/**
 * It is important that this class is not called from multiple threads
 * 
 * @author HardCoded
 * @date 2020-11-25
 */
class CodeSyntaxTreeUnit {
	private final CodeSyntaxTreeAnalyser utils;
	private List<NodeFunction> functions;
	private TracedFunction trace;
	private boolean debug;
	
	public CodeSyntaxTreeUnit(CodeSyntaxTreeAnalyser utils) {
		this.utils = utils;
		this.trace = new TracedFunction();
		this.functions = new ArrayList<>();
	}
	
	public void clean() {
		functions.clear();
	}
	
	public void setDebug(boolean enable) {
		this.debug = enable;
	}
	
	public List<NodeFunction> getFunctionsCopy() {
		return List.copyOf(functions);
	}
	
	public TracedFunction getTrace() {
		return trace;
	}
	
	private NodeFunction node;
	public void process(NodeFunction node, PcodeOp op) {
		process_basic(node, op);
		
		switch(op.getOpcode()) {
			case PcodeOp.CALL: {
				ExternalLocation location = utils.getExternalLocation(op.getInput(0));
				
				if(debug) {
					Varnode output = op.getOutput();
					System.out.printf("::::: Calling (%s) (%s) -> out %s\n", location, op, output);
					
					Varnode[] inputs = utils.getInputs(op, node);
					for(int i = 1; i < inputs.length; i++) {
						System.out.printf(":::::     %2d: %-30s\n", i, inputs[i]);
					}
				}
				
				if(location == null || !location.getLibraryName().toUpperCase().startsWith("LUA")) break;
				this.node = node;
				
				switch(location.getLabel()) {
					case "lua_getmetatable":
					case "lua_getfield":
					case "lua_createtable":
					case "lua_settable":
					case "lua_newuserdata":
					case "lua_setmetatable":
					case "lua_settop":
					case "lua_topointer":
					case "lua_toboolean":
					case "lua_isuserdata":
					case "lua_touserdata":
					case "lua_next":
					case "luaL_ref":
					case "lua_objlen":
					case "lua_rawequal":
					case "lua_rawseti":
					case "lua_rawset":
					case "lua_rawgeti":
					case "lua_rawget":
					case "lua_remove":
						break;
					
					// Complex to use for analysis
					case "lua_type":  // Returns the type of value at the specified index
					case "lua_isnumber": // Checks if the argument is a number
					case "lua_typename":
					case "lua_pushlstring":
					case "lua_pushboolean":
					case "lua_pushinteger":
					case "lua_pushnumber":
					case "lua_pushstring":
					case "lua_pushvalue":
					case "lua_pushnil":
					case "lua_gettop": // Used to get the size of the stack.
						break;
					
					case "luaL_error": luaL_error(op); break;
					case "luaL_checklstring": luaL_checklstring(op); break;
					case "luaL_checkinteger": luaL_checkinteger(op); break;
					case "luaL_checknumber": luaL_checknumber(op); break;
					case "luaL_checktype": luaL_checktype(op); break;
					case "lua_pushfstring": /* lua_pushfstring(op); */ break;
					case "luaL_argerror": luaL_argerror(op); break;
					case "luaL_checkudata": luaL_checkudata(op); break;
					default: {
						Varnode output = op.getOutput();
						System.out.printf("::::: Calling (%s) -> out %s\n", location, output);
						
						Varnode[] inputs = utils.getInputs(op, node);
						for(int i = 1; i < inputs.length; i++) {
							System.out.printf(":::::     %2d: %-30s\n", i, inputs[i]);
						}
					}
				}
			}
		}
	}
	
	public void process_basic(NodeFunction node, PcodeOp op) {
		if(op.getOpcode() != PcodeOp.CALL) return;
		if(!node.searchFurther) return;
		
		ExternalLocation location = utils.getExternalLocation(op.getInput(0));
		if(location != null) return;
		
		// System.out.println("Non external function: " + op);
		Address address = utils.getAddress(op.getInput(0));
		Varnode[] arguments = utils.getInputs(op, node);
		if(arguments.length > 0) {
			Varnode[] replace = new Varnode[arguments.length - 1];
			System.arraycopy(arguments, 1, replace, 0, replace.length);
			arguments = replace;
		}
		
		int argIndex = -1;
		if(node.luaParamIndex >= 0) {
			String luaParam = Objects.toString(node.parameters[node.luaParamIndex]);
			
			for(int i = 0; i < arguments.length; i++) {
				String str = Objects.toString(arguments[i], "<none>");
				if(luaParam.equals(str)) {
					argIndex = i;
					break;
				}
			}
		}
		
		NodeFunction child = new NodeFunction(address, argIndex, arguments);
		functions.add(child);
		
		return;
	}
	
	// char* luaL_checklstring (lua_State* L, int arg, size_t* s);
	private void luaL_checklstring(PcodeOp op) {
		if(op.getNumInputs() < 3) return; // TODO: Print why?
		
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		if(arg.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) trace.addType(id, "string");
		} else {
			System.out.println("1) luaL_checklstring: " + arg);
			System.out.println("2) luaL_checklstring: " + arg.getDef());
		}
	}
	
	// lua_Integer luaL_checkinteger (lua_State* L, int narg);
	private void luaL_checkinteger(PcodeOp op) {
		if(op.getNumInputs() < 3) return;
		
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		if(arg.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) trace.addType(id, "integer");
		}
	}
	
	// lua_Number luaL_checknumber (lua_State* L, int narg);
	private void luaL_checknumber(PcodeOp op) {
		if(op.getNumInputs() < 3) return;
		
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		if(arg.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) trace.addType(id, "number");
		}
	}
	
	// void luaL_checktype (lua_State* L, int narg, int t);
	private void luaL_checktype(PcodeOp op) {
		if(op.getNumInputs() < 4) return;
		
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		Varnode type = inputs[3];
		if(arg.isConstant() && type.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) {
				Type _type = utils.typeManager.getType((int)type.getOffset());
				trace.addType(id, _type);
				// trace.addType(id, LuaTypes.INSTANCE.getType((int)type.getOffset()).toString());
			}
		} else {
			System.out.println("::::: Calling (luaL_checktype) -> out ?");
			for(int i = 1; i < inputs.length; i++) {
				System.out.printf(":::::     %2d: %-30s %-30s\n", i, inputs[i], inputs[i].getDef());
			}
		}
	}
	
	// void* luaL_checkudata (lua_State* L, int narg, char* tname);
	private void luaL_checkudata(PcodeOp op) {
		Varnode[] inputs = utils.getInputs(op, node);
		
		if(debug) {
			System.out.println("::::: Calling (luaL_checkudata) -> out ?");
			for(int i = 1; i < inputs.length; i++) {
				System.out.printf(":::::     %2d: %-30s\n", i, inputs[i]);
			}
		}
		
		if(op.getNumInputs() < 4) return;
		
		Varnode arg = inputs[2];
		Varnode type = inputs[3];
		
		if(arg.isConstant() && type.isConstant()) {
			long id = arg.getOffset();
			String typestr = utils.resolveConstantString(type);
			
			if(id > 0 && typestr != null) {
				trace.addType(id, typestr.toLowerCase());
			}
		}
	}
	
	// char* lua_pushfstring (lua_State *L, char* fmt, ...);
//	private void lua_pushfstring(PcodeOp op) {
//		Varnode[] inputs = utils.getInputs(op, node);
//		System.out.println("======================================================================");
//		Varnode node = inputs[2];
//		String message = utils.resolveUniqueString(node);
//		System.out.println("lua_pushfstring: \"" + message + "\"");
//		
//		for(int i = 1; i < inputs.length; i++) {
//			System.out.printf("    %2d: %s\n", i, inputs[i]);
//		}
//	}
	
	// int luaL_argerror (lua_State* L, int narg, char* extramsg);
	private void luaL_argerror(PcodeOp op) {
		if(op.getNumInputs() < 4) return;
		
		Varnode[] inputs = utils.getInputs(op, node);
		PcodeOp[] pushst = new PcodeOp[inputs.length];
		
		for(int i = 1; i < inputs.length; i++) {
			Varnode input = inputs[i];
			//System.out.printf(":::::     %2d: %-30s %-30s\n", i, input, input.getDef());
			PcodeOp def = input.getDef();
			
			if(def != null && def.getOpcode() == PcodeOp.CALL) {
				ExternalLocation location = utils.getExternalLocation(def.getInput(0));
				if(location == null || !location.getLabel().equals("lua_pushfstring")) continue;
				pushst[i] = def;
			}
		}
		
		Varnode index = inputs[2];
		PcodeOp pushs = pushst[3];
		
		if(!index.isConstant() || pushs == null) {
			return;
		}
		
		{
			Varnode[] pushin = utils.getInputs(pushs, node);
			String format = utils.resolveConstantStringNoNull(pushin[2]);
			
			// Expected userdata, got %s
			if(format.endsWith(" expected, got %s")) {
				format = format.substring(0, format.length() - 17);
				if(format.endsWith("%s")) {
					if(pushin.length > 3) {
						String text_1 = utils.resolveConstantString(pushin[3]);
						if(text_1 != null) {
							trace.addType(index.getOffset(), text_1.toLowerCase());
						}
					} else {
						// bad!
					}
				} else {
					// Finite number is already handled.
					if(format.indexOf(" ") == -1) {
						trace.addType(index.getOffset(), format.toLowerCase());
					}
				}
			} else {
				System.out.println("======================================================================");
				System.out.println("Calling (LUA51.DLL::luaL_argerror) -> out ?");
				System.out.println(":: format = " + format);
				
				for(int i = 1; i < inputs.length; i++) {
					Varnode input = inputs[i];
					System.out.printf(":::::     %2d: %-30s %-30s\n", i, input, input.getDef());
				}
			}
		}
	}
	
	// int luaL_error (lua_State* L, char* fmt, ...);
	private void luaL_error(PcodeOp op) {
		if(op.getNumInputs() < 3) return;
		
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode node_format = inputs[2];
		if(!node_format.isConstant()) {
//			System.out.println("======================================================================");
//			System.out.println("luaL_error: node_format was not constant?");
//			System.out.println("op: " + op);
//			System.out.println("node: " + node_format);
			return;
		}
		
		String format = utils.resolveConstantStringNoNull(node_format);
		if(format.startsWith("Expected %d arguments")) {
			if(inputs.length < 4) return;
			long args = inputs[3].getOffset();
			trace.maximum_args = args;
			trace.minimum_args = args;
		} else if(format.startsWith("Expected at most %d arguments")) {
			if(inputs.length < 4) return;
			trace.maximum_args = inputs[3].getOffset();
		} else if(format.startsWith("Expected at least %d arguments")) {
			if(inputs.length < 4) return;
			trace.minimum_args = inputs[3].getOffset();
		} else if(format.startsWith("Sandbox violation: calling %s function from")) {
			if(inputs.length < 4) return;
			trace.sandbox = utils.resolveConstantString(inputs[3]);
		} else {
			// These could change and there are nothing we can do to estimate them
			resolveUnsafe(format, op, inputs);
		}
	}
	
	// Could change probably.
	private void resolveUnsafe(String format, PcodeOp op, Varnode[] inputs) {
	 	if(format.startsWith("Sandbox violation: ")
	 	|| format.startsWith("%s does not exist")) {
			// Do nothing here
	 		return;
		}
	 	
	 	// getClosestBlockLocalPosition expected a shape with the uuid of a block, received: {%s}
	 	// Created shape expected the uuid of a block, received: {%s}
	 	
	 	
	 	// If second is stack and third is const and there is no more params it is highly likely that this is
	 	// expecting the argument "Expected" at the position "const"
	 	
	 	// Invalid projectile attack source. Expected a Shape, but received:
	 	// Invalid projectile attack source. Expected a Harvestable, but received:
	 	
		/*
		======================================================================
		luaL_error: Unknown error message 'Invalid projectile attack source. Expected a Harvestable, but received:'
		     3: (register, 0x0, 4)             (register, 0x0, 4) CALL (ram, 0x6dff80, 8) , (stack, 0x4, 4) , (const, 0x6, 4)
		*/
	 	if(format.startsWith("Invalid projectile attack source. Expected a Player or Unit, but received:")) {
	 		if(inputs.length < 4) return;
	 		PcodeOp def = inputs[3].getDef();
	 		
	 		if(def == null) return;
	 		Varnode[] defin = utils.getInputs(def, node);
	 		if(defin.length < 3) return;
	 		
	 		switch(def.getOpcode()) {
		 		case PcodeOp.CALL: {
		 			ExternalLocation location = utils.getExternalLocation(defin[0]);
					if(location == null || !location.getLibraryName().toUpperCase().startsWith("LUA")) break;
					
					switch(location.getLabel()) {
						case "lua_type": {
							Varnode idx = defin[2];
							
							if(idx.isConstant()) {
								trace.addType(idx.getOffset(), "player");
								trace.addType(idx.getOffset(), "unit");
							}
						}
					}
		 		}
	 		}
	 	} else if(inputs.length > 3) {
	 		System.out.println("======================================================================");
			System.out.println("luaL_error: Unknown error message '" + format + "'");
			for(int i = 3; i < inputs.length; i++) {
				System.out.printf("    %2d: %-30s %-30s\n", i, inputs[i], inputs[i].getDef());
			}
	 	}
	}
}
