package sm.hardcoded.plugin.exporter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import sm.hardcoded.plugin.html.SMHtml;
import sm.hardcoded.plugin.tracer.SMClass;
import sm.hardcoded.plugin.tracer.SMPrefs;

public class Test {
	public static void main(String[] args) throws IOException {
		File file = new File("C:/Users/Admin/.smtracer/traces/lua.0.4.8.620.time.1606597301324.txt");
		
		FileInputStream in = new FileInputStream(file);
		byte[] bytes = in.readAllBytes();
		in.close();
		
		SMClass table = JsonExporter.deserialize(JsonParser.parse(bytes));
		System.out.println(table.getClass("shape").toString());
		
		SMPrefs prefs = new SMPrefs();
		SMHtml.generate(prefs, "0.4.8.testing", table);
	}
}
