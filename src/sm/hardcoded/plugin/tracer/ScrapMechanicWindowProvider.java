package sm.hardcoded.plugin.tracer;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.plugintool.ComponentProviderAdapter;

public class ScrapMechanicWindowProvider extends ComponentProviderAdapter {
	private final ScrapMechanicPlugin plugin;
	private GhidraFileChooser fileChooser;
	
	private JComponent mainPanel;
	
	ScrapMechanicWindowProvider(ScrapMechanicPlugin tool) {
		super(tool.getTool(), "ScrapMechanic Analyser", tool.getName());
		plugin = tool;
		
		createComponent();
	}
	
	public JComponent getComponent() {
		return mainPanel;
	}
	
	private JLabel label_status;
	private JLabel label_version;
	private JLabel label_functions;
	private JTextField textField_savePath;
	private JTextArea textArea_logging;
	private JProgressBar progressBar;
	private JButton btnScan;
	private JButton btnResetScan;
	
	private JComboBox<Integer> comboBox_threads;
	private JComboBox<Integer> comboBox_searchDepth;
	
	public void setStatusText(String string) {
		if(label_status != null)
			label_status.setText(string);
	}
	
	public void setVersionText(String string) {
		if(label_version != null)
			label_version.setText(string);
	}
	
	public void setFunctionsText(String string) { 
		if(label_functions != null)
			label_functions.setText(string);
	}
	
	public void setScanEnabled(boolean b) {
		if(btnScan != null)
			btnScan.setEnabled(b);
	}
	
	public void setResetScanEnabled(boolean b) {
		// The reset scan button is not good enough right now..
		// TODO: Update the bookmark manager gui when you press the reset scan button.
		// TODO: Update the button when the bookmark manager has changed.
		
		//if(btnResetScan != null)
		//    btnResetScan.setEnabled(b);
	}
	
	
	
	public void setProgressBar(double percentage) {
		setProgressBar(percentage, 100);
	}
	
	public void setProgressBar(double percentage, int max) {
		if(progressBar == null) return;
		
		int value = (int)(percentage * 10000);
		if(value < 0) value = 0;
		if(value > 10000) value = 10000;
		
		progressBar.setValue(value);
		progressBar.setString((value / 100) + " %");
	}
	
	public void writeLog(Object caller, String string) {
		if(textArea_logging == null) return;
		
		StringBuilder sb = new StringBuilder();
		sb.append(textArea_logging.getText());
		
		if(sb.length() != 0) sb.append('\n');
		sb.append(caller.getClass().getSimpleName()).append(": ").append(string);
		textArea_logging.setText(sb.toString());
	}
	
	public void clearLogger() {
		if(textArea_logging != null)
			textArea_logging.setText("");
	}
	
	///////////////////////////////////////////////////
	// Properties                                    //
	///////////////////////////////////////////////////
	
	public int getThreads() {
		if(comboBox_threads == null) return 1;
		return comboBox_threads.getSelectedIndex() + 1;
	}
	
	public int getSearchDepth() {
		if(comboBox_searchDepth == null) return 1;
		return comboBox_searchDepth.getSelectedIndex() + 1;
	}
	
	public String getSavePath() {
		if(textField_savePath == null) return null; // TODO: Default path
		return textField_savePath.getText();
	}
	
	public void setThreads(int threads) {
		if(comboBox_threads == null) return;
		
		if(threads > comboBox_threads.getItemCount() + 1) {
			threads = comboBox_threads.getItemCount() - 1;
		}
		
		comboBox_threads.setSelectedIndex(threads - 1);
	}
	
	public void setSearchDepth(int searchDepth) {
		if(comboBox_searchDepth == null) return;
		
		if(searchDepth > comboBox_searchDepth.getItemCount() + 1) {
			searchDepth = comboBox_searchDepth.getItemCount() - 1;
		}
		
		comboBox_searchDepth.setSelectedIndex(searchDepth - 1);
	}
	
	public void setSavePath(String savePath) {
		if(textField_savePath == null) return;
		textField_savePath.setText(getValidSavePath(savePath));
	}
	
	private String getValidSavePath(String savePath) {
		if(savePath == null) {
			String pluginHome = getPluginHome();
			File tracesPath = new File(pluginHome, "traces");
			savePath = tracesPath.getAbsolutePath();
		} else {
			File tracesPath = new File(savePath);
			if(!tracesPath.exists() || !tracesPath.isDirectory()) {
				String pluginHome = getPluginHome();
				tracesPath = new File(pluginHome, "traces");
				savePath = tracesPath.getAbsolutePath();
			}
		}
		
		return savePath;
	}
	
	private String getPluginHome() {
		String userHome = System.getProperty("user.home");
		File pluginHome = new File(userHome, "ScrapMechanicGhidraPlugin");
		if(!pluginHome.exists()) pluginHome.mkdir();
		
		File tracePath = new File(pluginHome, "traces");
		if(!tracePath.exists()) tracePath.mkdir();
		
		return pluginHome.getAbsolutePath();
	}
	
	private void createComponent() {
		mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.X_AXIS));
		
		JPanel panelInformation = new JPanel();
		panelInformation.setMinimumSize(new Dimension(160, 10));
		panelInformation.setPreferredSize(new Dimension(160, 10));
		panelInformation.setMaximumSize(new Dimension(160, 32767));
		panelInformation.setBorder(new TitledBorder(null, "Information", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		mainPanel.add(panelInformation);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{0, 0, 0};
		gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panelInformation.setLayout(gbl_panel);
		
		JLabel lblStatus = new JLabel("Status");
		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblNewLabel.insets = new Insets(5, 5, 25, 5);
		gbc_lblNewLabel.gridx = 0;
		gbc_lblNewLabel.gridy = 0;
		panelInformation.add(lblStatus, gbc_lblNewLabel);
		
		label_status = new JLabel("Not Analysed");
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.anchor = GridBagConstraints.NORTHEAST;
		gbc_lblNewLabel_1.insets = new Insets(5, 0, 25, 5);
		gbc_lblNewLabel_1.gridx = 1;
		gbc_lblNewLabel_1.gridy = 0;
		panelInformation.add(label_status, gbc_lblNewLabel_1);
		
		JLabel lblInformation = new JLabel("Information");
		GridBagConstraints gbc_lblInformation = new GridBagConstraints();
		gbc_lblInformation.anchor = GridBagConstraints.WEST;
		gbc_lblInformation.insets = new Insets(0, 5, 5, 5);
		gbc_lblInformation.gridx = 0;
		gbc_lblInformation.gridy = 1;
		panelInformation.add(lblInformation, gbc_lblInformation);
		
		JLabel lblVersion = new JLabel("Version");
		lblVersion.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.anchor = GridBagConstraints.WEST;
		gbc_lblVersion.insets = new Insets(0, 15, 5, 5);
		gbc_lblVersion.gridx = 0;
		gbc_lblVersion.gridy = 2;
		panelInformation.add(lblVersion, gbc_lblVersion);
		
		label_version = new JLabel("0.4.6.578");
		GridBagConstraints gbc_lblNewLabel_13 = new GridBagConstraints();
		gbc_lblNewLabel_13.anchor = GridBagConstraints.EAST;
		gbc_lblNewLabel_13.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_13.gridx = 1;
		gbc_lblNewLabel_13.gridy = 2;
		panelInformation.add(label_version, gbc_lblNewLabel_13);
		
		JLabel lblFunctions = new JLabel("Functions");
		GridBagConstraints gbc_lblFunctions = new GridBagConstraints();
		gbc_lblFunctions.anchor = GridBagConstraints.WEST;
		gbc_lblFunctions.insets = new Insets(0, 15, 0, 5);
		gbc_lblFunctions.gridx = 0;
		gbc_lblFunctions.gridy = 3;
		panelInformation.add(lblFunctions, gbc_lblFunctions);
		
		label_functions = new JLabel("1107");
		GridBagConstraints gbc_label_1 = new GridBagConstraints();
		gbc_label_1.insets = new Insets(0, 0, 0, 5);
		gbc_label_1.anchor = GridBagConstraints.EAST;
		gbc_label_1.gridx = 1;
		gbc_label_1.gridy = 3;
		panelInformation.add(label_functions, gbc_label_1);
		
		JPanel panel_1 = new JPanel();
		mainPanel.add(panel_1);
		panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.Y_AXIS));
		
		JPanel panelSettings = new JPanel();
		panelSettings.setBorder(new TitledBorder(null, "Settings", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel_1.add(panelSettings);
		GridBagLayout gbl_panel_2 = new GridBagLayout();
		gbl_panel_2.columnWidths = new int[]{0, 0, 0};
		gbl_panel_2.rowHeights = new int[]{0, 0, 0, 0, 0};
		gbl_panel_2.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_2.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panelSettings.setLayout(gbl_panel_2);
		
		JLabel lblSavePath = new JLabel("Trace Save Path");
		GridBagConstraints gbc_lblNewLabel_12 = new GridBagConstraints();
		gbc_lblNewLabel_12.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_12.insets = new Insets(0, 5, 5, 30);
		gbc_lblNewLabel_12.gridx = 0;
		gbc_lblNewLabel_12.gridy = 0;
		panelSettings.add(lblSavePath, gbc_lblNewLabel_12);
		
		JPanel panel_4 = new JPanel();
		GridBagConstraints gbc_panel_4 = new GridBagConstraints();
		gbc_panel_4.insets = new Insets(0, 0, 5, 0);
		gbc_panel_4.fill = GridBagConstraints.BOTH;
		gbc_panel_4.gridx = 1;
		gbc_panel_4.gridy = 0;
		panelSettings.add(panel_4, gbc_panel_4);
		panel_4.setLayout(new BoxLayout(panel_4, BoxLayout.X_AXIS));
		
		textField_savePath = new JTextField();
		textField_savePath.setEditable(false);
		textField_savePath.setText((String) null);
		textField_savePath.setMinimumSize(new Dimension(6, 21));
		textField_savePath.setMaximumSize(new Dimension(2147483647, 21));
		textField_savePath.setMargin(new Insets(0, 3, 0, 0));
		textField_savePath.setDisabledTextColor(Color.WHITE);
		textField_savePath.setColumns(10);
		panel_4.add(textField_savePath);
		
		fileChooser = new GhidraFileChooser(mainPanel);
		fileChooser.setMultiSelectionEnabled(false);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		
		JButton btnBrowserPath = new JButton("Browser");
		btnBrowserPath.setHorizontalAlignment(SwingConstants.LEADING);
		btnBrowserPath.setFocusable(false);
		btnBrowserPath.setAlignmentX(1.0f);
		btnBrowserPath.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(fileChooser.isShowing()) return;
				fileChooser.setCurrentDirectory(new File(getValidSavePath(textField_savePath.getText())));
				
				File file = fileChooser.getSelectedFile();
				if(file != null) {
					textField_savePath.setText(file.getAbsolutePath());
					fileChooser.close();
				}
			}
		});
		panel_4.add(btnBrowserPath);
		
		Component horizontalStrut_3 = Box.createHorizontalStrut(-1);
		panel_4.add(horizontalStrut_3);
		
		JLabel lblThreads = new JLabel("Threads");
		GridBagConstraints gbc_lblDecompileThreads = new GridBagConstraints();
		gbc_lblDecompileThreads.anchor = GridBagConstraints.WEST;
		gbc_lblDecompileThreads.insets = new Insets(0, 5, 5, 5);
		gbc_lblDecompileThreads.gridx = 0;
		gbc_lblDecompileThreads.gridy = 1;
		panelSettings.add(lblThreads, gbc_lblDecompileThreads);
		
		comboBox_threads = new JComboBox<Integer>();
		comboBox_threads.setFocusable(false);
		{
			Integer[] array = new Integer[Runtime.getRuntime().availableProcessors() - 1];
			for(int i = 0; i < array.length; i++) array[i] = Integer.valueOf(i + 1);
			comboBox_threads.setModel(new DefaultComboBoxModel<>(array));
			comboBox_threads.setSelectedIndex(array.length - 1);
		}
		
		GridBagConstraints gbc_comboBox = new GridBagConstraints();
		gbc_comboBox.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox.gridx = 1;
		gbc_comboBox.gridy = 1;
		panelSettings.add(comboBox_threads, gbc_comboBox);
		
		JLabel lblSearchDepth = new JLabel("Max Search Depth");
		GridBagConstraints gbc_lblNewLabel_2 = new GridBagConstraints();
		gbc_lblNewLabel_2.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_2.insets = new Insets(0, 5, 5, 5);
		gbc_lblNewLabel_2.gridx = 0;
		gbc_lblNewLabel_2.gridy = 2;
		panelSettings.add(lblSearchDepth, gbc_lblNewLabel_2);
		
		comboBox_searchDepth = new JComboBox<Integer>();
		comboBox_searchDepth.setFocusable(false);
		comboBox_searchDepth.setModel(new DefaultComboBoxModel<>(new Integer[] { 1, 2, 3, 4, 5 }));
		GridBagConstraints gbc_comboBox_1 = new GridBagConstraints();
		gbc_comboBox_1.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox_1.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox_1.gridx = 1;
		gbc_comboBox_1.gridy = 2;
		panelSettings.add(comboBox_searchDepth, gbc_comboBox_1);
		
		btnResetScan = new JButton("Reset Scan Data");
		GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
		gbc_btnNewButton_1.insets = new Insets(0, -1, 0, -1);
		gbc_btnNewButton_1.fill = GridBagConstraints.BOTH;
		gbc_btnNewButton_1.gridx = 1;
		gbc_btnNewButton_1.gridy = 3;
		panelSettings.add(btnResetScan, gbc_btnNewButton_1);
		btnResetScan.setEnabled(false);
		btnResetScan.setFocusable(false);
		btnResetScan.addActionListener((e) -> {
			plugin.getBookmarkManager().clearBookmarks();
			btnResetScan.setEnabled(false);
		});
		
		JPanel panelData = new JPanel();
		panelData.setPreferredSize(new Dimension(10, 32767));
		panelData.setBorder(new TitledBorder(null, "Data", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel_1.add(panelData);
		GridBagLayout gbl_panelData = new GridBagLayout();
		gbl_panelData.columnWidths = new int[]{0, 0, 0};
		gbl_panelData.rowHeights = new int[]{0, 0, 0};
		gbl_panelData.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
		gbl_panelData.rowWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		panelData.setLayout(gbl_panelData);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.insets = new Insets(0, 1, 5, 0);
		gbc_scrollPane.gridwidth = 2;
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 0;
		panelData.add(scrollPane, gbc_scrollPane);
		
		textArea_logging = new JTextArea();
		textArea_logging.setFont(new Font("Monospaced", Font.PLAIN, 11));
		textArea_logging.setEditable(false);
		textArea_logging.setDisabledTextColor(Color.BLACK);
		scrollPane.setViewportView(textArea_logging);
		
		btnScan = new JButton("Scan");
		btnScan.setFocusable(false);
		btnScan.setEnabled(plugin.getCurrentProgram() != null);
		GridBagConstraints gbc_btnNewButton_133 = new GridBagConstraints();
		gbc_btnNewButton_133.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnNewButton_133.anchor = GridBagConstraints.WEST;
		gbc_btnNewButton_133.insets = new Insets(0, 0, 0, 5);
		gbc_btnNewButton_133.gridx = 0;
		gbc_btnNewButton_133.gridy = 1;
		panelData.add(btnScan, gbc_btnNewButton_133);
		btnScan.addActionListener((event) -> {
			plugin.startScan();
		});
		
		progressBar = new JProgressBar();
		progressBar.setPreferredSize(new Dimension(146, 22));
		progressBar.setMaximumSize(new Dimension(32767, 22));
		progressBar.setMinimumSize(new Dimension(10, 22));
		progressBar.setMaximum(10000);
		progressBar.setStringPainted(true);
		GridBagConstraints gbc_progressBar = new GridBagConstraints();
		gbc_progressBar.anchor = GridBagConstraints.SOUTH;
		gbc_progressBar.fill = GridBagConstraints.HORIZONTAL;
		gbc_progressBar.gridx = 1;
		gbc_progressBar.gridy = 1;
		panelData.add(progressBar, gbc_progressBar);
	}
}
