package sm.importer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import sm.complex.ScrapMechanic;
import sm.util.FunctionUtil;
import sm.util.Util;

/**
 * This class imports the function signatures for each lua command.
 * It also imports some important datatypes.
 * 
 * lua_State, luaCFunction, lua_Integer, lua_Number, luaL_Reg
 * 
 * @author HardCoded
 */
public class Importer {
	public static final String LUA_STATE =
		"typedef struct lua_State lua_State;";
	
	public static final String LUA_CFUNCTION =
		"int lua_CFunction(lua_State* L);";
	
	public static final String LUA_INTEGER =
		"typedef int lua_Integer;";
	
	public static final String LUA_NUMBER =
		"typedef double lua_Number;";
	
	public static final String LUAL_REG =
		"typedef struct luaL_Reg {\n" +
			"const char* name;\n" +
			"lua_CFunction* func;\n" +
		"} luaL_Reg;";
	
	private static final String[][] FUNCTIONS = {
		{ "lua_State", LUA_STATE },
		{ "lua_Integer", LUA_INTEGER },
		{ "lua_Number", LUA_NUMBER },
		{ "lua_CFunction", LUA_CFUNCTION },
		{ "luaL_Reg", LUAL_REG },
		
		
		// Without this datatype, some functions will not get parsed by the CParser
		{ "size_t", "typedef unsigned int size_t;" }
	};
	
	private static DataTypeManager manager;
	private static Category luaPath;
	private static Category root;
	
	public static void init(GhidraScript ghidra) throws Exception {
		manager = ghidra.getCurrentProgram().getDataTypeManager();
		root = manager.getRootCategory();
		
		if(!root.getName().equals(ScrapMechanic.ROOT_NAME)) {
			// TODO: What if the executable is renamed at some point????
			
			throw new Exception("Invalid Executable Selected, Expected 'ScrapMechanic.exe' got '" + root.getName() + '"');
		}
		
		loadDataTypes(ghidra);
		loadFunctionSignatures(ghidra);
		initDirectories(ghidra);
	}
	
	private static void initDirectories(GhidraScript ghidra) throws Exception {
		String userHome = System.getProperty("user.home");
		
		File path = new File(userHome, "ScrapMechanicTracer/traces");
		if(!path.exists()) {
			path.mkdirs();
		}
	}
	
	private static boolean loadDataTypes(GhidraScript ghidra) throws Exception {
		boolean hasChanged = false;
		luaPath = root.getCategory("lua.h");
		if(luaPath == null) {
			System.out.println("Adding 'lua.h' category");
			luaPath = root.createCategory("lua.h");
			hasChanged = true;
		}
		
		for(String[] type : FUNCTIONS) {
			String name = type[0];
			String code = type[1];
			
			DataType typePath = luaPath.getDataType(name);
			if(typePath == null) {
				System.out.println("Adding dataType '" + name + "'");
				
				CParser parser = new CParser(manager);
				DataType dataType = parser.parse(code);
				dataType.setCategoryPath(luaPath.getCategoryPath());
				luaPath.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
				
				hasChanged = true;
			}
		}
		
		return hasChanged;
	}
	
	private static final String[][] SIGNATURES = {
		// NOTE: This was creating a java.lang.StackOverflowError exception because a DataType was not found. (Probably)
		// 	     Original signature "lua_CFunction* lua_atpanic (lua_State* L, lua_CFunction* panicf);"
		{ "lua_atpanic",			"void* lua_atpanic (lua_State* L, lua_CFunction* panicf);" },
		
		{ "lua_call",				"void lua_call (lua_State* L, int nargs, int nresults);" },
		{ "lua_close",				"void lua_close (lua_State* L);" },
		{ "lua_createtable",		"void lua_createtable (lua_State* L, int narr, int nrec);" },
		{ "lua_getfield",			"void lua_getfield (lua_State* L, int index, char* k);" },
		{ "lua_getmetatable",		"int lua_getmetatable (lua_State* L, int index);" },
		{ "lua_gettop",				"int lua_gettop (lua_State* L);" },
		{ "lua_insert",				"void lua_insert (lua_State* L, int index);" },
		{ "lua_isnumber",			"int lua_isnumber (lua_State* L, int index);" },
		{ "lua_isstring",			"int lua_isstring (lua_State* L, int index);" },
		{ "lua_isuserdata",			"int lua_isuserdata (lua_State* L, int index);" },
		{ "lua_newuserdata",		"void* lua_newuserdata (lua_State* L, size_t size);" },
		{ "lua_next",				"int lua_next (lua_State* L, int index);" },
		{ "lua_objlen",				"size_t lua_objlen (lua_State* L, int index);" },
		{ "lua_pcall",				"int lua_pcall (lua_State* L, int nargs, int nresults, int errfunc);" },
		{ "lua_pushboolean",		"void lua_pushboolean (lua_State *L, int b);" },
		{ "lua_pushcclosure",		"void lua_pushcclosure (lua_State *L, lua_CFunction* fn, int n);" },
		{ "lua_pushfstring",		"char* lua_pushfstring (lua_State *L, char* fmt, ...);" },
		{ "lua_pushinteger",		"void lua_pushinteger (lua_State *L, lua_Integer n);" },
		
		{ "lua_pushlightuserdata",	"void lua_pushlightuserdata (lua_State* L, void* p);" },
		{ "lua_pushlstring",		"void lua_pushlstring (lua_State* L, char* s, size_t len);" },
		{ "lua_pushnil",			"void lua_pushnil (lua_State* L);" },
		{ "lua_pushnumber",			"void lua_pushnumber (lua_State* L, lua_Number n);" },
		{ "lua_pushstring",			"void lua_pushstring (lua_State* L, char* s);" },
		{ "lua_pushvalue",			"void lua_pushvalue (lua_State* L, int index);" },
		
		{ "lua_rawequal",			"int lua_rawequal (lua_State* L, int index1, int index2);" },
		{ "lua_rawget",				"void lua_rawget (lua_State* L, int index);" },
		{ "lua_rawgeti",			"void lua_rawgeti (lua_State* L, int index, int n);" },
		{ "lua_rawset",				"void lua_rawset (lua_State* L, int index);" },
		{ "lua_rawseti",			"void lua_rawseti (lua_State* L, int index, int n);" },
		{ "lua_remove",				"void lua_remove (lua_State* L, int index);" },
		{ "lua_setfenv",			"int lua_setfenv (lua_State* L, int index);" },
		{ "lua_setfield",			"void lua_setfield (lua_State* L, int index, char* k);" },
		{ "lua_setmetatable",		"int lua_setmetatable (lua_State* L, int index);" },
		{ "lua_settable",			"void lua_settable (lua_State* L, int index);" },
		{ "lua_settop",				"void lua_settop (lua_State* L, int index);" },
		
		{ "lua_toboolean",			"int lua_toboolean (lua_State* L, int index);" },
		{ "lua_topointer",			"void* lua_topointer (lua_State* L, int index);" },
		{ "lua_touserdata",			"void* lua_touserdata (lua_State* L, int index);" },
		{ "lua_type",				"int lua_type (lua_State* L, int index);" },
		{ "lua_typename",			"char* lua_typename  (lua_State* L, int tp);" },
		{ "luaL_argerror",			"int luaL_argerror (lua_State* L, int narg, char* extramsg);" },
		{ "luaL_checkinteger",		"lua_Integer luaL_checkinteger (lua_State* L, int narg);" },
		{ "luaL_checklstring",		"char* luaL_checklstring (lua_State* L, int narg, size_t* s);" },
		{ "luaL_checknumber",		"lua_Number luaL_checknumber (lua_State* L, int narg);" },
		{ "luaL_checktype",			"void luaL_checktype (lua_State* L, int narg, int t);" },
		{ "luaL_checkudata",		"void* luaL_checkudata (lua_State* L, int narg, char* tname);" },
		
		{ "luaL_error",				"int luaL_error (lua_State* L, char* fmt, ...);" },
		{ "luaL_loadbuffer",		"int luaL_loadbuffer (lua_State* L, char* buff, size_t sz, char* name);" },
		{ "luaL_loadstring",		"int luaL_loadstring (lua_State* L, char* s);" },
		{ "luaL_newmetatable",		"int luaL_newmetatable (lua_State* L, char* tname);" },
		{ "luaL_newstate",			"lua_State* luaL_newstate ();" },
		{ "luaL_ref",				"int luaL_ref (lua_State* L, int t);" },
		{ "luaL_register",			"void luaL_register (lua_State* L, char* libname, luaL_Reg* l);" },
		{ "luaL_traceback",			"void luaL_traceback (lua_State* L, lua_State* L1, char* msg, int level);" },
		{ "luaL_unref",				"void luaL_unref (lua_State *L, int t, int ref);" },
		

		{ "luaopen_base",			"int luaopen_base (lua_State* L);" },
		{ "luaopen_bit",			"int luaopen_bit (lua_State* L);" },
		{ "luaopen_debug",			"int luaopen_debug (lua_State* L);" },
		{ "luaopen_ffi",			"int luaopen_ffi (lua_State* L);" },
		{ "luaopen_math",			"int luaopen_math (lua_State* L);" },
		{ "luaopen_os",				"int luaopen_os (lua_State* L);" },
		{ "luaopen_package",		"int luaopen_package (lua_State* L);" },
		{ "luaopen_string",			"int luaopen_string (lua_State* L);" },
		{ "luaopen_table",			"int luaopen_table (lua_State* L);" },
	};
	private static boolean loadFunctionSignatures(GhidraScript ghidra) throws Exception {
		boolean hasChanged = false;
		
		Program program = ghidra.getCurrentProgram();
		SymbolTable table = program.getSymbolTable();
		
		Symbol library = table.getLibrarySymbol(ScrapMechanic.LIBRARY_NAME);
		if(library == null) {
			throw new Exception("Failed to find the library '" + ScrapMechanic.LIBRARY_NAME + "'");
		}
		
		SymbolIterator iterator = table.getChildren(library);
		while(iterator.hasNext()) {
			Symbol symbol = iterator.next();
			
			String[] data = getFunctionInformation(symbol.getName());
			if(data == null) {
				System.out.println("Unimplemented lua function found '" + symbol.getName() + "'");
				continue;
			}
			
			CParser parser = new CParser(manager);
			FunctionSignature signature = (FunctionSignature)parser.parse(data[1]);
			boolean shouldUpdate = isDifferent(symbol, signature);
			
			if(shouldUpdate) {
				System.out.println("Changing function signature '" + symbol.getName() + "' -> '" + data[1] + "'");
				hasChanged = true;
				
				ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
					symbol.getAddress(),
					signature,
					SourceType.USER_DEFINED,
					false,
					false
				);
				
				try {
					cmd.applyTo(program, Util.getMonitor());
				} catch(Throwable e) {
					ByteArrayOutputStream bs = new ByteArrayOutputStream();
					PrintStream stream = new PrintStream(bs);
					e.printStackTrace(stream);
					
					byte[] bytes = bs.toByteArray();
					System.out.println("Length: " + bytes.length);
					System.out.println("String: " + new String(bytes, 0, Math.min(2048, bytes.length)));
				}
			}
		}
		
		return hasChanged;
	}
	
	/**
	 * This function checks if the function referenced by the Symbol is different
	 * from the FunctionSignature.
	 * 
	 * @param symbol
	 * @param type
	 * @return if there is any difference between the two function signatures.
	 * @throws Exception
	 */
	private static boolean isDifferent(Symbol symbol, FunctionSignature type) throws Exception {
		Function function = FunctionUtil.createExternalFunction(symbol.getAddress(), symbol.getName());
		if(function == null || type == null) return false; // TODO: What do we do here?
		
		/*
		if(symbol.getObject() instanceof Function) {
			function = (Function)symbol.getObject();
		} else {
			throw new Exception("Symbol was not linked to a function ' " + symbol + " '");
		}*/
		
		if(!function.getCallingConventionName().equals("__cdecl")) {
			function.setCallingConvention("__cdecl");
			return true;
		}
		
		if(!function.getReturnType().isEquivalent(type.getReturnType())) return true;
		
		ParameterDefinition[] arguments = type.getArguments();
		if(function.getParameterCount() != arguments.length) return true;
		
		Parameter[] params = function.getParameters();
		for(int i = 0; i < params.length; i++) {
			DataType target = arguments[i].getDataType();
			DataType param = params[i].getDataType();
			
			if(!param.isEquivalent(target)) {
				return true;
			}
		}
		
		return false;
	}
	
	private static String[] getFunctionInformation(String label) {
		for(String[] data : SIGNATURES) {
			if(label.equals(data[0])) return data;
		}
		
		return null;
	}
}
