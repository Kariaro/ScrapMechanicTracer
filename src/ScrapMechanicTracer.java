// @author HardCoded
// @category ScrapMechanicTracer
// @keybinding 
// @menupath 
// @toolbar 

import java.io.File;

import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;
import sm.importer.Importer;
import sm.importer.PointerFinder;
import sm.util.CacheUtil;
import sm.util.LuaUtil;
import sm.util.ScrapMechanic;
import sm.util.Util;

/**
 * This ghidra script is used to print the ScrapMechanic lua structure to a file.
 * It will get the different functions and all the arguments to each function.
 * 
 * @author HardCoded
 */
public class ScrapMechanicTracer extends GhidraScript implements Ingredient {
	public static final void main(String[] args) {
		System.out.println("[Hopefully this will get compiled :&]");
	}
	
	// NOTE: Must analyse 'Decompile Parameter ID'
	// NOTE: ??? Does it need to analyse 'Function ID'
	
	// TODO: Create a nice gui for this scanner.
	
	public void run() throws Exception {
		DevUtil.replacePrintStreams(this);
		DevUtil.replaceGhidraBin(this);
		
		IngredientDescription[] ingredients = getIngredientDescriptions();
		for(int i = 0; i < ingredients.length; i++) {
			IngredientDescription ingredient = ingredients[i];
			
			state.addParameter(
				ingredient.getID(),
				ingredient.getLabel(),
				ingredient.getType(),
				ingredient.getDefaultValue()
			);
		}
		
		if(!state.displayParameterGatherer("ScrapMechanicTracer Options")) {
			return;
		}
		
		// state.getEnvironmentVar(< id >);
		
		//DomainFolder folder = askProjectFolder("Please select a project folder to RECURSIVELY look for a named function:");
		
		// Initialize the util
		Util.init(this);
		
		// Initialize all imports
		Importer.init(this);
		
		// Load all lua functions
		LuaUtil.init(this);
		
		// Find all the structure pointers
		PointerFinder.init(this);
		
		// Initialize the cache
		CacheUtil.init(DevUtil.classPath);
		
		// Start the application
		println("--------------------------------------------------------------------------");
		
		long start = System.currentTimeMillis();
		
		{
			try {
				ScrapMechanic.launch();
			} catch(Exception e) {
				e.printStackTrace();
			}
			
			String type_str = LuaUtil.getTypes().values().toString();
			type_str = type_str.substring(1, type_str.length() - 1);
			type_str = type_str.replace(", ", "\n  ");
			System.out.println("LuaTypes:\n  " + type_str + "\n");
		}
		
		long ellapsed = System.currentTimeMillis() - start;
		println("Time ellapsed: " + ellapsed + " ms");

		println("--------------------------------------------------------------------------");
	}
	
	// private static final String STRINGS_MEMORY_BLOCK = ".rdata";
	// private static final String REFERENCES_MEMORY_BLOCK = ".data";
	@Override
	public IngredientDescription[] getIngredientDescriptions() {
		IngredientDescription[] retVal = new IngredientDescription[] {
			new IngredientDescription("STRINGS_MEMORY_BLOCK",		"Strings", GatherParamPanel.STRING, ".rdata"),
			new IngredientDescription("REFERENCES_MEMORY_BLOCK",	"References", GatherParamPanel.STRING, ".data"),
			new IngredientDescription("OUTPUT_FILE",				"Output file", GatherParamPanel.FILE, "")
		};
		return retVal;
	}

}
                                  