package sm.util;

import sm.complex.SMStructure;

public class ScrapMechanic {
	private ScrapMechanic() {
		
	}
	
	public static final void launch() {
		/*FunctionExplorer3 explorer = new FunctionExplorer3();
		try {
			// 006e2200
			// Load_sm_render
			//LuaReg reg = new LuaReg("00fe3e10", "Load_sm_gui_interface", "006df3a0");
			//LuaReg reg = new LuaReg("00fdc158", "Load_sm_localPlayer_006e1d00", "006e1d00");
			LuaReg reg = new LuaReg("00fe3dc8", "Load_sm_tool_006e7070", "006e7070");
			SMObject smobj = SMUtil.loadSMObject(reg);
			
			SMContainer con = new SMContainer();
			SMClassObject clazz = con.addClass("sm.tool");
			clazz.loadSettings(smobj);
			clazz.loadConstants(smobj);
			clazz.loadFunctions(smobj);
			
			
			Set<SMFunctionObject> functions = con.getAllFunctions();
			
			for(SMFunctionObject obj : functions) {
				if(!obj.getName().equals("checkLiftCollision")) continue;
				System.out.printf("Exploring: %s\n", obj);
				explorer.evaluate(obj);
				break;
			}
			
			for(SMFunctionObject obj : functions) {
				if(obj.getFuzzedFunction() == null) continue;
				System.out.println(obj);
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		explorer.close();
		*/
		
		SMStructure structure = new SMStructure(false);
		
		System.out.println("Generated structure: " + structure);
		structure.evaluate();
		
	}
}
