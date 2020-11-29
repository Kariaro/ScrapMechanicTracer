package sm.hardcoded.plugin.html;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import resources.ResourceManager;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeAnalyser.TracedFunction;
import sm.hardcoded.plugin.tracer.Logger;
import sm.hardcoded.plugin.tracer.SMClass;
import sm.hardcoded.plugin.tracer.SMClass.Constant;
import sm.hardcoded.plugin.tracer.SMClass.Function;
import sm.hardcoded.plugin.tracer.SMPrefs;

/**
 * This class creates a html page that contains more information about
 * each function.
 * 
 * @author HardCoded
 * @date 2020-11-27
 */
public class SMHtml {
	private final String INDEX_TEMPLATE;
	private final String TREE_TEMPLATE;
	private final String PANEL_TEMPLATE;
	
	private final SMPrefs prefs;
	private final String version;
	private final SMClass table;
	
	private List<TreeNode> nodes;
	private File docsPath;
	private File docsPagesPath;
	
	private SMHtml(SMPrefs prefs, String version, SMClass table) {
		this.prefs = prefs;
		this.version = version;
		this.table = table;
		this.nodes = new ArrayList<>();
		
		String treeTemplate = "";
		String panelTemplate = "";
		String indexTemplate = "";
		try {
			InputStream stream;
			
			stream = ResourceManager.getResourceAsStream("html/tree_template.html");
			treeTemplate = new String(stream.readAllBytes());
			stream.close();
			
			stream = ResourceManager.getResourceAsStream("html/panel_template.html");
			panelTemplate = new String(stream.readAllBytes());
			stream.close();
			
			stream = ResourceManager.getResourceAsStream("html/index_template.html");
			indexTemplate = new String(stream.readAllBytes());
			stream.close();
		} catch(IOException e) {
			Logger.log(e);
		}
		
		TREE_TEMPLATE = treeTemplate;
		PANEL_TEMPLATE = panelTemplate;
		INDEX_TEMPLATE = indexTemplate;
	}
	
	
	private void loadNodes() {
		List<SMClass> list = new ArrayList<>(table.getClasses());
		
		while(!list.isEmpty()) {
			SMClass node = list.get(0);
			list.remove(0);
			list.addAll(0, node.getClasses());
			nodes.add(new TreeNode(node.getPath(), node));
		}
	}
	
	private void initPaths() {
		docsPath = new File(prefs.getTracePath(), version + "." + System.currentTimeMillis());
		if(!docsPath.exists()) docsPath.mkdir();
		
		docsPagesPath = new File(docsPath, "docs");
		if(!docsPagesPath.exists()) docsPagesPath.mkdir();
	}
	
	private void writeFile(File file, String content) {
		try(FileOutputStream stream = new FileOutputStream(file)) {
			stream.write(content.getBytes());
		} catch(IOException e) {
			Logger.log(e);
		}
	}
	
	private void generateIndexTemplate() {
		String content = INDEX_TEMPLATE.replace("{TITLE}", version);
		File test = new File(docsPath, "index.html");
		writeFile(test, content);
	}
	
	private void generateTreeTemplate() {
		String content = TREE_TEMPLATE.replace("{VERSION}", version);
		
		// TODO: Target panel needs to exist.
		StringBuilder sb = new StringBuilder();
		for(TreeNode node : nodes) {
			sb.append("<li><a target=\"view\" href=\"docs/").append(node.path.replace(".", "_")).append(".html\">")
			  .append(node.path).append("</a></li>");
		}
		content = content.replace("{TREE}", sb.toString());
		
		File test = new File(docsPath, "tree.html");
		writeFile(test, content);
	}
	
	private void generatePanelTemplate(TreeNode node) {
		String content = PANEL_TEMPLATE;
		
		{
			StringBuilder constants = new StringBuilder();
			for(Constant con : node.clazz.getConstants()) {
				String str = String.format("<p class=\"ms\"><a href=\"#c_%s\">%s</a></p>",
					con.getName(),
					con.toString()
				);
				constants.append(str);
			}
			
			StringBuilder tabledata = new StringBuilder();
			StringBuilder userdata = new StringBuilder();
			for(Function func : node.clazz.getFunctions()) {
				if(func.isUserdata()) {
					String str = String.format("<p class=\"ms\"><a href=\"#u_%s\">%s</a></p>",
						func.getName(),
						func.toString()
					);
					userdata.append(str);
				} else {
					String str = String.format("<p class=\"ms\"><a href=\"#f_%s\">%s</a></p>",
						func.getName(),
						func.toString()
					);
					tabledata.append(str);
				}
			}
			
			content = content.replace("{TABLE_CONSTANTS}", constants.toString());
			content = content.replace("{TABLE_TABLEDATA}", tabledata.toString());
			content = content.replace("{TABLE_USERDATA}", userdata.toString());
		}
		
		{
			StringBuilder constants = new StringBuilder();
			for(Constant con : node.clazz.getConstants()) {
				constants.append(generateConstant(con));
			}
			
			StringBuilder tabledata = new StringBuilder();
			StringBuilder userdata = new StringBuilder();
			for(Function func : node.clazz.getFunctions()) {
				if(func.isUserdata()) {
					userdata.append(generateFunction(func));
				} else {
					tabledata.append(generateFunction(func));
				}
			}
			
			content = content.replace("{CONSTANTS}", constants.toString());
			content = content.replace("{TABLEDATA}", tabledata.toString());
			content = content.replace("{USERDATA}", userdata.toString());
		}
		
		String name = node.path.replace(".", "_") + ".html";
		File test = new File(docsPagesPath, name);
		writeFile(test, content);
		
		// <li><a target="view" href="panel.html#sm.physics">sm.physics</a></li>
	}
	
	private void generateDocsTemplate() {
		for(TreeNode node : nodes) {
			generatePanelTemplate(node);
		}
	}
	
	// FIXME: make sure that no xss has been injected.
	// TODO: Remove all whitespaces and comments
	public void start() {
		loadNodes();
		initPaths();
		
		generateIndexTemplate();
		generateTreeTemplate();
		generateDocsTemplate();
	}
	
	public static void generate(SMPrefs prefs, String version, SMClass clazz) {
		SMHtml html = new SMHtml(prefs, version, clazz);
		html.start();
	}
	
	private static String generateFunction(Function func) {
		String template =
"<a name=\"{LINK}\"></a>\n" +
"<li class=\"function\">\n" +
"	<div class=\"functionHeader\">{NAME}</div>\n" +
"	<div class=\"functionContent\">\n" +
"		<pre>{DATA}</pre>\n" +
"		<span class=\"sandbox\">{SANDBOX}</span><br>\n" +
"	</div>\n" +
"</li>";
		
		String result = template.replace("{NAME}", func.getName())
								.replace("{DATA}", func.toString())
								.replace("{LINK}", (func.isUserdata() ? "u_":"f_") + func.getName());
		
		TracedFunction trace = func.getTrace();
		String sandbox = "";
		if(trace != null) {
			String traceSandbox = trace.getSandbox();
			if(!sandbox.isBlank()) {
				sandbox = "[" + traceSandbox + "]";
			}
		}
		
		result = result.replace("{SANDBOX}", sandbox);
		
		return result;
	}
	
	private static String generateConstant(Constant con) {
		String template =
"<a name=\"{LINK}\"></a>\n" +
"<li class=\"function\">\n" +
"	<div class=\"functionHeader\">{NAME}</div>\n" +
"	<div class=\"functionContent\">\n" +
"		<pre>{DATA}</pre>\n" +
"		<span class=\"sandbox\">{SANDBOX}</span><br>\n" +
"	</div>\n" +
"</li>";
		
		String result = template.replace("{NAME}", con.getName())
								.replace("{DATA}", con.toString())
								.replace("{LINK}", "c_" + con.getName());
		
//		TracedFunction trace = func.getTrace();
//		String sandbox = "";
//		if(trace != null) {
//			String traceSandbox = trace.getSandbox();
//			if(!sandbox.isBlank()) {
//				sandbox = "[" + traceSandbox + "]";
//			}
//		}
//		
//		result = result.replace("{SANDBOX}", sandbox);
		
		return result;
	}
	
	private static class TreeNode {
		public final String path;
		public final SMClass clazz;
		
		public TreeNode(String path, SMClass clazz) {
			this.path = path;
			this.clazz = clazz;
		}
		
		public String toString() {
			return path;
		}
	}
}
