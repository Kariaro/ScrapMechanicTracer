package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.NodeFunction;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.TracedFunction;

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
	
	public void process(HighFunction hf, NodeFunction node, PcodeOp op) {
		int opcode = op.getOpcode();
		Varnode output = op.getOutput();
		
		// TODO: We need to be able to recover information about what this function was called with
		//       We need to know all the parameters and mappings so that we can continue to
		//       search for arguments.
		
		switch(opcode) {
			case PcodeOp.CALL: {
				ExternalLocation location = utils.getExternalLocation(op.getInput(0));
				if(location == null) {
					if(node.searchFurther) {
						System.out.println("Non external function: " + op);
						boolean searchFurther = false;
						// Add functions when they have (stack 0x4) or if they are belonging to a function
						// that had lua functions.
						
						for(int i = 1; i < op.getNumInputs(); i++) {
							System.out.printf("    %2d: %s\n", i, op.getInput(i));
						}
						
						functions.add(new NodeFunction(utils.getAddress(op.getInput(0)), searchFurther, -1));
					}
					
					return;
				}
				
				if(!location.getLibraryName().toUpperCase().startsWith("LUA")) break;
				
				switch(location.getLabel()) {
					case "lua_getmetatable":
					case "lua_getfield":
					case "lua_settop": break;
					case "lua_toboolean": break;
					case "luaL_argerror": break; // Check this function
					
					// Complex to use for analysis
					case "lua_type":  // Returns the type of value at the specified index
					case "lua_typename":
					case "lua_gettop": // Used to get the size of the stack.
						break;
					
					case "luaL_error": luaL_error(op); break;
					case "luaL_checklstring": luaL_checklstring(op); break;
					case "luaL_checkinteger": luaL_checkinteger(op); break;
					case "luaL_checknumber": luaL_checknumber(op); break;
					case "lua_pushfstring": lua_pushfstring(op); break;
					case "lua_isnumber": // Checks if the argument is a number
					default: {
						System.out.printf("Calling (%s) -> out %s\n", location, output);
						
						for(int i = 1; i < op.getNumInputs(); i++) {
							System.out.printf("    %2d: %s\n", i, op.getInput(i));
						}
					}
				}
			}
		}
	}
	
	// char* luaL_checklstring (lua_State* L, int arg, size_t* s);
	private void luaL_checklstring(PcodeOp op) {
		Varnode arg = op.getInput(2);
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
		Varnode arg = op.getInput(2);
		if(arg.isConstant()) {
			long id = arg.getOffset();
			if(id > 0) trace.addType(id, "integer");
		}
	}
	
	// lua_Number luaL_checknumber (lua_State* L, int narg);
	private void luaL_checknumber(PcodeOp op) {
		Varnode arg = op.getInput(2);
		if(arg.isConstant()) {
			long id = arg.getOffset();
			if(id > 1) trace.addType(id, "number");
		}
	}
	
	private void lua_pushfstring(PcodeOp op) {
		System.out.println("======================================================================");
		Varnode node = op.getInput(2);
		String message = utils.resolveUniqueString(node);
		System.out.println("lua_pushfstring: \"" + message + "\"");
		
		for(int i = 1; i < op.getNumInputs(); i++) {
			System.out.printf("    %2d: %s\n", i, op.getInput(i));
		}
	}
	
	// int luaL_error (lua_State* L, char* fmt, ...);
	private void luaL_error(PcodeOp op) {
		// op.getInput(1) is the lua_State*
		
		Varnode node_format = op.getInput(2);
		if(!node_format.isUnique()) {
			System.out.println("======================================================================");
			System.out.println("luaL_error: node_format was not unique?");
			System.out.println("op: " + op);
			System.out.println("node: " + node_format);
			return;
		}
		
		String format = utils.resolveUniqueString(node_format);
		if(format.startsWith("Expected %d arguments")) {
			long args = op.getInput(3).getOffset();
			trace.maximum_args = args;
			trace.minimum_args = args;
		} else if(format.startsWith("Expected at most %d arguments")) {
			long args = op.getInput(3).getOffset();
			trace.maximum_args = args;
		} else if(format.startsWith("Expected at least %d arguments")) {
			long args = op.getInput(3).getOffset();
			trace.minimum_args = args;
		} else if(format.startsWith("Sandbox violation: calling %s function from")) {
			trace.sandbox = utils.resolveUniqueString(op.getInput(3));
		} else {
			System.out.println("======================================================================");
			System.out.println("luaL_error: Unknown error message '" + format + "'");
			for(int i = 3; i < op.getNumInputs(); i++) {
				System.out.printf("    %2d: %s\n", i, op.getInput(i));
			}
		}
	}
}
