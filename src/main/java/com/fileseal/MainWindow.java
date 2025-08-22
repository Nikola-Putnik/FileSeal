package com.fileseal;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;

public class MainWindow extends JFrame {

    private JTextField extensionField;
    private JComboBox<String> hashTypeComboBox;
    private JTextArea logArea;
    private File selectedFolder; // Dossier sélectionné

    public MainWindow() {
        setTitle("FileSeal");
        setSize(800, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        initUI();

        setVisible(true);
    }

    private void initUI() {
        // ---------- TOP PANEL ----------
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        JButton selectFolderButton = new JButton("Select folder");
        extensionField = new JTextField(".mkv", 6);
        hashTypeComboBox = new JComboBox<>(new String[]{"MD5", "SHA-1", "SHA-256"});
        JButton generateButton = new JButton("Generate hashes");
        JButton verifyButton = new JButton("Verify hashes"); // TO-DO

        // "Select folder" button action
        selectFolderButton.addActionListener((ActionEvent e) -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select a folder");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);

            int result = chooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedFolder = chooser.getSelectedFile();
                log("Selected folder: " + selectedFolder.getAbsolutePath());
            } else {
                log("Folder selection cancelled.");
            }
        });

        // "Generate hashes" button action
        generateButton.addActionListener((ActionEvent e) -> {
            if (selectedFolder == null || !selectedFolder.isDirectory()) {
                log("No folder selected.");
                return;
            }

            String extension = extensionField.getText().trim();
            if (!extension.startsWith(".")) {
                extension = "." + extension;
            }

            String algo = (String) hashTypeComboBox.getSelectedItem();

            File[] files = selectedFolder.listFiles();
            if (files == null || files.length == 0) {
                log("No files found in the folder.");
                return;
            }

            for (File file : files) {
                if (file.isFile() && file.getName().toLowerCase().endsWith(extension)) {
                    try {
                        String hash = computeHash(file, algo);
                        String hashExtension = algo.toLowerCase().replace("-", "");
                        String hashFilename = file.getAbsolutePath() + "." + hashExtension;
                        File hashFile = new File(hashFilename);
                        try (java.io.FileWriter fw = new java.io.FileWriter(hashFile)) {
                            fw.write(algo.toUpperCase() + ": " + hash + "  " + file.getName());
                        }
                        log("OK : " + file.getName() + " → " + hash);
                    } catch (Exception ex) {
                        log("Error processing : " + file.getName() + ": " + ex.getMessage());
                    }
                }
            }
        });

        // "Verify hashes" button action
        verifyButton.addActionListener((ActionEvent e) -> {
            log("TO-DO");
        });

        gbc.gridx = 0; gbc.gridy = 0;
        topPanel.add(selectFolderButton, gbc);

        gbc.gridx = 1;
        topPanel.add(new JLabel("Extension:"), gbc);
        gbc.gridx = 2;
        topPanel.add(extensionField, gbc);

        gbc.gridx = 3;
        topPanel.add(new JLabel("Hash type:"), gbc);
        gbc.gridx = 4;
        topPanel.add(hashTypeComboBox, gbc);

        gbc.gridx = 5;
        topPanel.add(generateButton, gbc);

        gbc.gridx = 6;
        topPanel.add(verifyButton, gbc);

        // ---------- LOG AREA ----------
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(logArea);

        // ---------- MAIN LAYOUT ----------
        setLayout(new BorderLayout());
        add(topPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    // displays messages in LOG AERA)
    private void log(String message) {
        logArea.append(message + "\n");
    }

    // calculates the hash
    private String computeHash(File file, String algorithm) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance(algorithm);
        try (java.io.InputStream is = new java.io.FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }

        byte[] hashBytes = digest.digest();

        // Convert to hexa
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}