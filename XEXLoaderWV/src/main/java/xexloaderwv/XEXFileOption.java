
package xexloaderwv;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextField;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.util.AddressFactoryService;
import ghidra.app.util.importer.options.StringOption;
import ghidra.util.filechooser.ExtensionFileFilter;

public class XEXFileOption extends StringOption {
	private final String[] extensions;
	private final String description;

	public XEXFileOption(String name, String value, String extension, String description) {
		this(name, value, new String[] { extension }, description);
	}

	public XEXFileOption(String name, String value, String[] extensions, String description) {
		super(name, value, null, null, null, false, description);
		this.extensions = extensions.clone();
		this.description = description;
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		JTextField field = (JTextField) super.getCustomEditorComponent(addressFactoryService);
		field.setColumns(25);
		JButton browse = new JButton("...");
		JPanel panel = new JPanel(new BorderLayout(5, 0));
		panel.add(field, BorderLayout.CENTER);
		panel.add(browse, BorderLayout.EAST);
		browse.addActionListener(e -> {
			GhidraFileChooser chooser = new GhidraFileChooser(panel);
			try {
				chooser.setTitle(description);
				chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
				chooser.setFileFilter(new ExtensionFileFilter(extensions, description));
				if (!field.getText().isBlank())
					chooser.setSelectedFile(new File(field.getText()));
				File selected = chooser.getSelectedFile();
				if (selected != null)
					field.setText(selected.getAbsolutePath());
			} finally {
				chooser.dispose();
			}
		});
		return panel;
	}

	@Override
	public XEXFileOption copy() {
		return new XEXFileOption(getName(), getValue(), extensions, description);
	}
}
