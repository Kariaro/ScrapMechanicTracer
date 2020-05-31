import sm.util.LuaUtil;
import sm.util.ScrapMechanic;

class ProgramStart {
	public static void start() {
		ScrapMechanic sm = new ScrapMechanic();
		// server:  00fe35d8
		// client:  00fe3dc8
		// both:    00ff9888
		// storage: 00fe36a8
		
		try {
			sm.test();
			
			
			/*
			SMStruct struct = sm.createBuilder()
				.loadSM("00fe35d8") // server
				.loadSM("00fe3dc8") // client
				.loadSM("00ff9888") // both
				.loadSM("00fe36a8") // storage [Server Only]
				.build();
			
			System.out.println(struct.traceFully());
			*/
			/*
			SMContainer.load(
				"00fe35d8",
				"00fe3dc8",
				"00ff9888",
				"00fe36a8"
			);
			*/
			/*
			List<SMObject> list = sm.createObjectBuilder()
				.loadSM("00fe35d8") // server
				.loadSM("00fe3dc8") // client
				.loadSM("00ff9888") // both
				.loadSM("00fe36a8") // storage [Server Only]
				.build();
			
			SMStruct struct = sm.loadFromSMObjects(list);
			
			
			String list_str = list.toString();
			list_str = list_str.substring(1, list_str.length() - 1);
			list_str = list_str.replace("}, ", "}\n  ");
			System.out.println("LuaRefs:\n  " + list_str + "\n");
			
			System.out.println(struct + "\n");
			*/
			
			String type_str = LuaUtil.getTypes().values().toString();
			type_str = type_str.substring(1, type_str.length() - 1);
			type_str = type_str.replace(", ", "\n  ");
			System.out.println("LuaTypes:\n  " + type_str + "\n");
			
		} catch(Exception e) {
			e.printStackTrace();
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
}
