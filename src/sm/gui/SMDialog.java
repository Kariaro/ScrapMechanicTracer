package sm.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import sm.util.CacheUtil;
import sm.util.Util;

public class SMDialog extends JFrame {
	private static final long serialVersionUID = 8516907091837622595L;
	
	private GhidraFileChooser fileChooser;
	private JComboBox<String> comboBox_stringsMemory;
	private JComboBox<String> comboBox_referencesMemory;
	private JComboBox<String> comboBox_threads;
	private JComboBox<String> comboBox_exploreDepth;
	private JProgressBar progressBar;
	private JSpinner spinner;
	
	private JButton btnNewButton;
	private JButton btnStopFuzzing;
	
	private transient Runnable fuzzingListener;
	
	public SMDialog(GhidraScript ghidra) {
		setMinimumSize(new Dimension(360, 166));
		setIconImage(Toolkit.getDefaultToolkit().getImage(SMDialog.class.getResource("/images/greenDragon16.png")));
		String[] memoryComboBoxValues = new String[] { "Search All" };
		
		if(ghidra != null) {
			List<String> names = new ArrayList<>();
			MemoryBlock[] blocks = ghidra.getCurrentProgram().getMemory().getBlocks();
			
			for(MemoryBlock block : blocks) {
				names.add(block.getName());
			}
			
			String[] namesArray = names.toArray(String[]::new);
			String[] newArray = new String[names.size() + 1];
			newArray[0] = "Search All";
			System.arraycopy(namesArray, 0, newArray, 1, names.size());
			memoryComboBoxValues = newArray;
		}
		
		String[] threadValues = new String[] { "1" };
		if(ghidra != null) {
			int cores = Math.max(1, Runtime.getRuntime().availableProcessors() - 1);
			threadValues = new String[cores];
			for(int i = 0; i < cores; i++) {
				threadValues[i] = String.valueOf(i + 1);
			}
		}
		
		setTitle("ScrapMechanic Fuzzing Functions");
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		
		setBounds(100, 100, 645, 353);
		JPanel contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));
		
		JPanel panel_3 = new JPanel();
		panel_3.setBorder(new EmptyBorder(1, 1, 1, 2));
		contentPane.add(panel_3, BorderLayout.SOUTH);
		panel_3.setLayout(new BoxLayout(panel_3, BoxLayout.X_AXIS));
		
		btnNewButton = new JButton("Start Fuzzing");
		btnNewButton.setEnabled(ghidra != null);
		btnNewButton.setFocusable(false);
		panel_3.add(btnNewButton);
		
		btnStopFuzzing = new JButton("Stop Fuzzing");
		btnStopFuzzing.setEnabled(false);
		btnStopFuzzing.setFocusable(false);
		panel_3.add(btnStopFuzzing);
		btnNewButton.addActionListener((event) -> {
			if(fuzzingListener != null) {
				btnNewButton.setEnabled(false);
				btnStopFuzzing.setEnabled(true);
				
				Util.getMonitor().clearCanceled();
				Thread thread = new Thread(fuzzingListener);
				thread.start();
			}
		});
		btnStopFuzzing.addActionListener((event) -> {
			if(Util.isRunningGhidra()) Util.getMonitor().cancel();
		});
		
		Component horizontalStrut = Box.createHorizontalStrut(10);
		panel_3.add(horizontalStrut);
		
		JPanel panel_6 = new JPanel();
		panel_6.setFocusable(false);
		panel_6.setBorder(null);
		panel_3.add(panel_6);
		panel_6.setLayout(new BorderLayout(0, 0));
		
		progressBar = new JProgressBar();
		progressBar.setBorderPainted(false);
		panel_6.add(progressBar);
		progressBar.setPreferredSize(new Dimension(146, 22));
		progressBar.setFocusable(false);
		progressBar.setStringPainted(true);
		progressBar.setMaximumSize(new Dimension(32767, 23));
		progressBar.setForeground(new Color(46, 139, 87));
		progressBar.setString("");
		progressBar.setMinimumSize(new Dimension(10, 22));
		
		Component verticalStrut = Box.createVerticalStrut(1);
		panel_6.add(verticalStrut, BorderLayout.NORTH);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(null, "Advaned Options", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		contentPane.add(panel_1, BorderLayout.CENTER);
		panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.X_AXIS));
		
		JPanel panel_5 = new JPanel();
		panel_1.add(panel_5);
		GridBagLayout gbl_panel_5 = new GridBagLayout();
		gbl_panel_5.columnWidths = new int[]{0, 0, 0, 0};
		gbl_panel_5.rowHeights = new int[]{0, 0, 0, 0};
		gbl_panel_5.columnWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_5.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_5.setLayout(gbl_panel_5);
		
		JLabel lblNewLabel_3 = new JLabel("Decompile Threads");
		lblNewLabel_3.setToolTipText("The amount of threads that should run decompilers simultaneously");
		lblNewLabel_3.setHorizontalTextPosition(SwingConstants.CENTER);
		lblNewLabel_3.setHorizontalAlignment(SwingConstants.TRAILING);
		lblNewLabel_3.setFocusable(false);
		lblNewLabel_3.setPreferredSize(new Dimension(132, 14));
		lblNewLabel_3.setMinimumSize(new Dimension(132, 14));
		lblNewLabel_3.setMaximumSize(new Dimension(132, 14));
		GridBagConstraints gbc_lblNewLabel_3 = new GridBagConstraints();
		gbc_lblNewLabel_3.anchor = GridBagConstraints.EAST;
		gbc_lblNewLabel_3.insets = new Insets(0, 5, 5, 5);
		gbc_lblNewLabel_3.gridx = 0;
		gbc_lblNewLabel_3.gridy = 0;
		panel_5.add(lblNewLabel_3, gbc_lblNewLabel_3);
		
		Component horizontalStrut_2 = Box.createHorizontalStrut(20);
		GridBagConstraints gbc_horizontalStrut_2 = new GridBagConstraints();
		gbc_horizontalStrut_2.insets = new Insets(0, 0, 5, 5);
		gbc_horizontalStrut_2.gridx = 1;
		gbc_horizontalStrut_2.gridy = 0;
		panel_5.add(horizontalStrut_2, gbc_horizontalStrut_2);
		
		comboBox_threads = new JComboBox<>();
		comboBox_threads.setFocusable(false);
		comboBox_threads.setModel(new DefaultComboBoxModel<String>(threadValues));
		comboBox_threads.setSelectedItem(
			CacheUtil.getProperty("decompiler.threads", threadValues[threadValues.length - 1])
		);
		comboBox_threads.addActionListener((event) -> {
			CacheUtil.setProperty("decompiler.threads", comboBox_threads.getSelectedItem());
		});
		GridBagConstraints gbc_textField = new GridBagConstraints();
		gbc_textField.insets = new Insets(0, 0, 5, 0);
		gbc_textField.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField.gridx = 2;
		gbc_textField.gridy = 0;
		panel_5.add(comboBox_threads, gbc_textField);
		
		JLabel lblDecompileTimeout = new JLabel("Decompile Timeout");
		lblDecompileTimeout.setToolTipText("The maximum amount of seconds that the decompiler is allowed to run on a task.Maximum 240 seconds");
		lblDecompileTimeout.setFocusable(false);
		lblDecompileTimeout.setHorizontalAlignment(SwingConstants.TRAILING);
		GridBagConstraints gbc_lblDecompileTimeout = new GridBagConstraints();
		gbc_lblDecompileTimeout.anchor = GridBagConstraints.EAST;
		gbc_lblDecompileTimeout.insets = new Insets(0, 5, 5, 5);
		gbc_lblDecompileTimeout.gridx = 0;
		gbc_lblDecompileTimeout.gridy = 1;
		panel_5.add(lblDecompileTimeout, gbc_lblDecompileTimeout);
		
		spinner = new JSpinner();
		spinner.setRequestFocusEnabled(false);
		spinner.setFocusTraversalKeysEnabled(false);
		spinner.setFocusable(false);
		spinner.setModel(new SpinnerNumberModel(10, 5, 240, 5));
		spinner.setValue(CacheUtil.getProperty("decompiler.timeout", "10", Integer::valueOf));
		spinner.addChangeListener((event) -> {
			CacheUtil.setProperty("decompiler.timeout", spinner.getValue());
		});
		GridBagConstraints gbc_spinner = new GridBagConstraints();
		gbc_spinner.fill = GridBagConstraints.HORIZONTAL;
		gbc_spinner.insets = new Insets(0, 0, 5, 0);
		gbc_spinner.gridx = 2;
		gbc_spinner.gridy = 1;
		panel_5.add(spinner, gbc_spinner);
		
		JLabel lblNewLabel_4 = new JLabel("Maximum Search Depth");
		lblNewLabel_4.setToolTipText("The maximum depth the ScrapMechanicFuzzer can search for lua information");
		GridBagConstraints gbc_lblNewLabel_4 = new GridBagConstraints();
		gbc_lblNewLabel_4.anchor = GridBagConstraints.EAST;
		gbc_lblNewLabel_4.insets = new Insets(0, 0, 0, 5);
		gbc_lblNewLabel_4.gridx = 0;
		gbc_lblNewLabel_4.gridy = 2;
		panel_5.add(lblNewLabel_4, gbc_lblNewLabel_4);
		
		comboBox_exploreDepth = new JComboBox<>();
		comboBox_exploreDepth.setFocusable(false);
		comboBox_exploreDepth.setModel(new DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5" }));
		comboBox_exploreDepth.setSelectedItem(CacheUtil.getProperty("decompiler.maxDepth", "3"));
		comboBox_exploreDepth.addActionListener((event) -> {
			CacheUtil.setProperty("decompiler.maxDepth", comboBox_exploreDepth.getSelectedItem());
		});
		GridBagConstraints gbc_comboBox_3 = new GridBagConstraints();
		gbc_comboBox_3.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox_3.gridx = 2;
		gbc_comboBox_3.gridy = 2;
		panel_5.add(comboBox_exploreDepth, gbc_comboBox_3);
		
		JPanel panel_4 = new JPanel();
		panel_4.setBorder(new TitledBorder(null, "Data options", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		contentPane.add(panel_4, BorderLayout.NORTH);
		panel_4.setLayout(new BoxLayout(panel_4, BoxLayout.X_AXIS));
		
		JPanel panel = new JPanel();
		panel.setFocusable(false);
		panel_4.add(panel);
		panel.setBorder(null);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{46, 0, 46, 0};
		gbl_panel.rowHeights = new int[]{14, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		JLabel lblNewLabel = new JLabel("Strings Memory Region");
		lblNewLabel.setToolTipText("The memory region that contains all strings");
		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.anchor = GridBagConstraints.EAST;
		gbc_lblNewLabel.insets = new Insets(0, 5, 5, 5);
		gbc_lblNewLabel.gridx = 0;
		gbc_lblNewLabel.gridy = 0;
		panel.add(lblNewLabel, gbc_lblNewLabel);
		
		Component horizontalStrut_1 = Box.createHorizontalStrut(20);
		GridBagConstraints gbc_horizontalStrut_1 = new GridBagConstraints();
		gbc_horizontalStrut_1.insets = new Insets(0, 0, 5, 5);
		gbc_horizontalStrut_1.gridx = 1;
		gbc_horizontalStrut_1.gridy = 0;
		panel.add(horizontalStrut_1, gbc_horizontalStrut_1);
		
		comboBox_stringsMemory = new JComboBox<>();
		comboBox_stringsMemory.setModel(new DefaultComboBoxModel<>(memoryComboBoxValues));
		comboBox_stringsMemory.setSelectedItem(CacheUtil.getProperty("strings.memoryblock", ".rdata"));
		comboBox_stringsMemory.addActionListener((event) -> {
			CacheUtil.setProperty("strings.memoryblock", comboBox_stringsMemory.getSelectedItem());
		});
		lblNewLabel.setLabelFor(comboBox_stringsMemory);
		comboBox_stringsMemory.setFocusable(false);
		GridBagConstraints gbc_comboBox = new GridBagConstraints();
		gbc_comboBox.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox.gridx = 2;
		gbc_comboBox.gridy = 0;
		panel.add(comboBox_stringsMemory, gbc_comboBox);
		
		JLabel lblNewLabel_1 = new JLabel("References Memory Region");
		lblNewLabel_1.setToolTipText("The memory region that points to the ScrapMechanic luaL_Reg structure pointers");
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.insets = new Insets(0, 5, 5, 5);
		gbc_lblNewLabel_1.anchor = GridBagConstraints.EAST;
		gbc_lblNewLabel_1.gridx = 0;
		gbc_lblNewLabel_1.gridy = 1;
		panel.add(lblNewLabel_1, gbc_lblNewLabel_1);
		
		comboBox_referencesMemory = new JComboBox<>();
		comboBox_referencesMemory.setModel(new DefaultComboBoxModel<>(memoryComboBoxValues));
		comboBox_referencesMemory.setSelectedItem(CacheUtil.getProperty("pointers.memoryblock", ".data"));
		comboBox_referencesMemory.addActionListener((event) -> {
			CacheUtil.setProperty("pointers.memoryblock", comboBox_referencesMemory.getSelectedItem());
		});
		lblNewLabel_1.setLabelFor(comboBox_referencesMemory);
		comboBox_referencesMemory.setFocusable(false);
		GridBagConstraints gbc_comboBox_1 = new GridBagConstraints();
		gbc_comboBox_1.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox_1.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox_1.gridx = 2;
		gbc_comboBox_1.gridy = 1;
		panel.add(comboBox_referencesMemory, gbc_comboBox_1);
		
		JLabel lblNewLabel_2 = new JLabel("Trace Save Path");
		lblNewLabel_2.setToolTipText("The save path of the trace");
		GridBagConstraints gbc_lblNewLabel_2 = new GridBagConstraints();
		gbc_lblNewLabel_2.anchor = GridBagConstraints.EAST;
		gbc_lblNewLabel_2.insets = new Insets(0, 5, 0, 5);
		gbc_lblNewLabel_2.gridx = 0;
		gbc_lblNewLabel_2.gridy = 2;
		panel.add(lblNewLabel_2, gbc_lblNewLabel_2);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(null);
		lblNewLabel_2.setLabelFor(panel_2);
		panel_2.setFocusable(false);
		GridBagConstraints gbc_panel_2 = new GridBagConstraints();
		gbc_panel_2.fill = GridBagConstraints.HORIZONTAL;
		gbc_panel_2.gridx = 2;
		gbc_panel_2.gridy = 2;
		panel.add(panel_2, gbc_panel_2);
		panel_2.setLayout(new BoxLayout(panel_2, BoxLayout.X_AXIS));
		
		JTextField filePathField = new JTextField();
		filePathField.setMinimumSize(new Dimension(6, 21));
		filePathField.setMaximumSize(new Dimension(2147483647, 21));
		filePathField.setDisabledTextColor(Color.WHITE);
		filePathField.setEditable(false);
		filePathField.setText(CacheUtil.getTracePath().getAbsolutePath());
		filePathField.setMargin(new Insets(0, 3, 0, 0));
		filePathField.setFocusable(false);
		panel_2.add(filePathField);
		filePathField.setColumns(10);
		
		fileChooser = new GhidraFileChooser(SMDialog.this);
		fileChooser.setMultiSelectionEnabled(false);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		fileChooser.setCurrentDirectory(CacheUtil.getTracePath().getParentFile());
		
		JButton btnNewButton_1 = new JButton("Browser");
		btnNewButton_1.setHorizontalAlignment(SwingConstants.LEADING);
		btnNewButton_1.setAlignmentX(Component.RIGHT_ALIGNMENT);
		btnNewButton_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(fileChooser.isShowing()) return;
				fileChooser.setCurrentDirectory(CacheUtil.getTracePath().getParentFile());
				
				File file = fileChooser.getSelectedFile();
				if(file != null) {
					filePathField.setText(file.getAbsolutePath());
					CacheUtil.setProperty("traces.path", file.getAbsolutePath());
					fileChooser.close();
				}
			}
		});
		btnNewButton_1.setFocusable(false);
		panel_2.add(btnNewButton_1);
		
		Component horizontalStrut_3 = Box.createHorizontalStrut(-1);
		panel_2.add(horizontalStrut_3);
		
		addWindowListener(new WindowListener() {
			public void windowOpened(WindowEvent e) {}
			public void windowIconified(WindowEvent e) {}
			public void windowDeiconified(WindowEvent e) {}
			public void windowDeactivated(WindowEvent e) {}
			public void windowClosing(WindowEvent e) {}
			public void windowActivated(WindowEvent e) {}
			
			@Override
			public void windowClosed(WindowEvent e) {
				CacheUtil.setProperty("traces.path", filePathField.getText());
				CacheUtil.setProperty("pointers.memoryblock", comboBox_referencesMemory.getSelectedItem());
				CacheUtil.setProperty("strings.memoryblock", comboBox_stringsMemory.getSelectedItem());
				CacheUtil.setProperty("decompiler.threads", comboBox_threads.getSelectedItem());
				CacheUtil.setProperty("decompiler.timeout", spinner.getValue());
				CacheUtil.setProperty("decompiler.maxDepth", comboBox_exploreDepth.getSelectedItem());
			}
		});
	}
	
	public void start() {
		setVisible(true);
	}
	
	public void setStartFuzzingListener(Runnable runnable) {
		fuzzingListener = runnable;
	}
	
	public void setMaximumProgress(int maximum) {
		progressBar.setMaximum(maximum);
	}
	
	public void setProgressIndex(int value) {
		progressBar.setValue(value);
		progressBar.setString(value + " / " + progressBar.getMaximum());
	}

	public void incrementProgress(int i) {
		int value = progressBar.getValue() + i;
		progressBar.setValue(value);
		progressBar.setString(value + " / " + progressBar.getMaximum());
	}
	
	public void stopFuzzing() {
		btnNewButton.setEnabled(true);
		btnStopFuzzing.setEnabled(false);
		progressBar.setString(progressBar.getString() + " [CLOSED]");
	}
}
