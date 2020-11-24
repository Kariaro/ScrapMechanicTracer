package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.NodeFunction;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.TracedFunction;

/**
 * It is important that this class is not called from multiple threads
 * 
 * @author HardCoded
 * @date 2020-11-24
 */
class CodeSyntaxTreeUnit {
	private final CodeSyntaxTreeUtils utils;
	private List<NodeFunction> functions;
	private TracedFunction trace;
	
	public CodeSyntaxTreeUnit(CodeSyntaxTreeUtils utils) {
		this.utils = utils;
		this.trace = new TracedFunction();
		this.functions = new ArrayList<>();
	}
	
	public void clean() {
		functions.clear();
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
		Varnode[] arguments = new Varnode[op.getNumInputs() - 1];
		for(int i = 1; i < op.getNumInputs(); i++) {
			arguments[i - 1] = op.getInput(i);
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
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		if(arg.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) trace.addType(id, "integer");
		}
	}
	
	// lua_Number luaL_checknumber (lua_State* L, int narg);
	private void luaL_checknumber(PcodeOp op) {
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		if(arg.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) trace.addType(id, "number");
		}
	}
	
	// void luaL_checktype (lua_State* L, int narg, int t);
	private void luaL_checktype(PcodeOp op) {
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		Varnode type = inputs[3];
		if(arg.isConstant() && type.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) {
				trace.addType(id, LuaTypes.INSTANCE.getType((int)type.getOffset()).toString());
			}
		}
	}
	
	// void* luaL_checkudata (lua_State* L, int narg, char* tname);
	private void luaL_checkudata(PcodeOp op) {
		Varnode[] inputs = utils.getInputs(op, node);
		Varnode arg = inputs[2];
		Varnode type = inputs[3];
		if(arg.isConstant() && type.isUnique()) {
			long id = arg.getOffset();
			String typestr = utils.resolveUniqueString(type);
			
//			System.out.println("::::: Calling (luaL_checkudata) -> out ?");
//			for(int i = 1; i < inputs.length; i++) {
//				System.out.printf(":::::     %2d: %-30s\n", i, inputs[i]);
//			}
			
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
		Varnode[] inputs = utils.getInputs(op, node);
		PcodeOp[] pushst = new PcodeOp[inputs.length];
		// Check if the getDef() connects to a lua_pushfstring
		// if so then take the string from it and replace the input!
		
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

		System.out.println("======================================================================");
		System.out.println("Calling (LUA51.DLL::luaL_argerror) -> out ?");
		{
			Varnode[] pushin = utils.getInputs(pushs, node);
			String format = utils.resolveUniqueString(pushin[2]);
			System.out.println(":: format = " + format);
			
			if(format.startsWith("%s expected, got %s")) {
				String text_1 = utils.resolveUniqueString(pushin[3]);
				if(text_1 != null) {
					System.out.println(":: text_1 = " + text_1);
					System.out.println(":: " + index);
					trace.addType(index.getOffset(), text_1.toLowerCase());
				}
			}
		}
	}
	
	// int luaL_error (lua_State* L, char* fmt, ...);
	private void luaL_error(PcodeOp op) {
		Varnode[] inputs = utils.getInputs(op, node);
		
		Varnode node_format = inputs[2];
		if(!node_format.isUnique()) {
//			System.out.println("======================================================================");
//			System.out.println("luaL_error: node_format was not unique?");
//			System.out.println("op: " + op);
//			System.out.println("node: " + node_format);
			return;
		}
		
		String format = utils.resolveUniqueString(node_format);
		if(format.startsWith("Expected %d arguments")) {
			long args = inputs[3].getOffset();
			trace.maximum_args = args;
			trace.minimum_args = args;
		} else if(format.startsWith("Expected at most %d arguments")) {
			long args = inputs[3].getOffset();
			trace.maximum_args = args;
		} else if(format.startsWith("Expected at least %d arguments")) {
			long args = inputs[3].getOffset();
			trace.minimum_args = args;
		} else if(format.startsWith("Sandbox violation: calling %s function from")) {
			trace.sandbox = utils.resolveUniqueString(inputs[3]);
		} else if(format.startsWith("Sandbox violation: ")) {
			// Do nothing here
		} else {
			System.out.println("======================================================================");
			System.out.println("luaL_error: Unknown error message '" + format + "'");
			for(int i = 3; i < inputs.length; i++) {
				System.out.printf("    %2d: %s\n", i, inputs[i]);
			}
		}
	}
}
