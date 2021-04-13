package com.hardcoded.plugin.exporter;

import java.io.*;

import com.hardcoded.plugin.json.JsonObject;
import com.hardcoded.plugin.json.JsonParser;

public class Test {
	public static void main(String[] args) throws IOException {
		File file = new File("C:/Users/Admin/.smtracer/traces/lua.0.4.8.620.test.json");
		File outputFile = new File("C:/Users/Admin/.smtracer/traces/simple.0.4.8.620.output.json");
		
		FileInputStream in = new FileInputStream(file);
		byte[] bytes = in.readAllBytes();
		in.close();
		
		JsonObject test = JsonParser.parse(bytes);
		
		JsonObject export = SmmJsonExporter.convert(test);
		
		FileOutputStream out = new FileOutputStream(outputFile);
		out.write(export.toString().getBytes());
		out.close();
		
		//SMClass table = JsonExporter.deserialize(JsonParser.parse(bytes));
		//Logger.log(table.getClass("shape").toString());
		//SMPrefs prefs = new SMPrefs();
		//SMHtml.generate(prefs, "0.4.8.testing", table);
	}
}
