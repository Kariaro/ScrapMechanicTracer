package sm.util;

import java.util.ArrayList;
import java.util.List;

import sm.SMObject;
import sm.complex.SMStructure;

public class ScrapMechanic {
	public ScrapMechanic() {
		
	}
	
	public SMObjectBuilder createObjectBuilder() throws Exception {
		return new SMObjectBuilder();
	}
	
	/*public SMStructBuilder createBuilder() throws Exception {
		/*if(false) {
			SMFunction value = new SMFunction("checkLiftCollision", "006e6700", true);
			value.load(parent);
			
			System.out.println(value);
			return null;
		}
		
		return new SMStructBuilder();
	}
	
	public SMStruct loadFromSMObjects(List<SMObject> objects) {
		return new SMStruct("sm").load(objects);
	}
	
	class SMStructBuilder {
		private SMStruct sm;
		
		private SMStructBuilder() {
			sm = new SMStruct("sm");
		}
		
		public SMStructBuilder loadSM(String address) throws Exception {
			
			// This will contain SMDataLink elements
			// that has the structure
			//   .. .. .. ..  addr  sm_namePointer
			//   .. .. .. ..  addr  sm_funcPointer
			SMDataStruct struct = new SMDataStruct(address);
			sm.addPointerTable(struct);
			
			for(SMDataLink link : struct) {
				// This class searches after the function pointers contained in the
				// namespace
				SMFunctionSearch_0 sm_object = new SMFunctionSearch_0(ghidra, link);
				
				for(SMDataLink entry : sm_object.getTabledata()) {
					// 1: name
					// 2: tabledata
					//SMFunction function = sm.addFunction(link, entry, false);
					//function.load();
				}
				
				for(SMDataLink entry : sm_object.getUserdata()) {
					// 1: userdata
					// 2: object_identifiers
					// 3: name
					//SMFunction function = sm.addFunction(link, entry, true);
					//function.load();
				}
			}
			
			return SMStructBuilder.this;
		}
		
		public SMStruct build() {
			return sm;
		}
	}*/
	
	public class SMObjectBuilder {
		private List<SMObject> list;
		private SMObjectBuilder() {
			list = new ArrayList<SMObject>();
		}
		
		public SMObjectBuilder loadSM(String address) throws Exception {
			LuaRegList array = new LuaRegList(address);
			for(LuaReg ref : array) {
				list.add(SMUtil.loadSMObject(ref));
			}
			return this;
		}
		
		public List<SMObject> build() {
			return list;
		}
	}

	public void test() {
		SMStructure structure = new SMStructure(false);
		
		System.out.println("Generated structure: " + structure);
		structure.evaluate();
		
		/*
		SMContainer container = null;//SMContainer.loadCache();
		if(container == null) {
			container = SMContainerBuilder.create()
				.loadSM("00fe35d8") // server
				.loadSM("00fe3dc8") // client
				.loadSM("00ff9888") // both
				.loadSM("00fe36a8") // storage [Server Only]
				.calculate()
				.runTests()
				.build();
			
			SMContainer.saveCache(container);
		}
		
		//System.out.println(container);
		 */
	}
}
