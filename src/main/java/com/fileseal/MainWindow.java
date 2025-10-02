package com.fileseal;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;

public class MainWindow extends JFrame {

    private JTextField extensionField;
    private JComboBox<String> hashTypeComboBox;
    private JTextArea logArea;
    private File selectedFolder;
    private JProgressBar progressBar;

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
            java.util.List<File> filesToHash = getAllFilesWithExtension(selectedFolder, extension);

            if (filesToHash.isEmpty()) {
                log("No matching files found.");
                return;
            }

            progressBar.setValue(0); // reset
            progressBar.setMaximum(filesToHash.size());

            SwingWorker<Void, Integer> worker = new SwingWorker<>() {
                @Override
                protected Void doInBackground() {
                    int processed = 0;

                    for (File file : filesToHash) {
                        try {
                            String hashExtension = algo.toLowerCase().replace("-", "");
                            String hashFilename = file.getAbsolutePath() + "." + hashExtension;
                            File hashFile = new File(hashFilename);

                            if (hashFile.exists()) {
                                log("⏭️ Skipped (already exists): " + hashFile.getName());
                            } else {
                                String hash = computeHash(file, algo);
                                try (java.io.FileWriter fw = new java.io.FileWriter(hashFile)) {
                                    fw.write(algo.toUpperCase() + ": " + hash + "  " + file.getName());
                                }
                                log("✅ " + file.getName() + " → " + hash);
                            }
                        } catch (Exception ex) {
                            log("❌ Error processing " + file.getName() + ": " + ex.getMessage());
                        }

                        processed++;
                        publish(processed);
                    }

                    return null;
                }

                @Override
                protected void process(java.util.List<Integer> chunks) {
                    int latest = chunks.get(chunks.size() - 1);
                    progressBar.setValue(latest);
                }

                @Override
                protected void done() {
                    log("✅ Done generating hashes.");
                }
            };

            log("Starting hash generation...");
            worker.execute();
        });

        // "Verify hashes" button action
        verifyButton.addActionListener((ActionEvent e) -> {
            if (selectedFolder == null || !selectedFolder.isDirectory()) {
                log("No folder selected.");
                return;
            }

            java.util.List<File> hashFiles = getAllHashFiles(selectedFolder);
            if (hashFiles.isEmpty()) {
                log("No hash files found (.md5, .sha1, .sha256).");
                return;
            }

            progressBar.setValue(0);
            progressBar.setMaximum(hashFiles.size());

            SwingWorker<Void, Integer> worker = new SwingWorker<>() {

                private int okCount = 0;
                private int errorCount = 0;
                private int totalCount = hashFiles.size();

                @Override
                protected Void doInBackground() {
                    int processed = 0;

                    for (File file : hashFiles) {
                        try {
                            java.util.List<String> lines = java.nio.file.Files.readAllLines(file.toPath());
                            if (lines.isEmpty()) {
                                log("Empty hash file: " + file.getName());
                                errorCount++;
                                continue;
                            }

                            String line = lines.get(0).trim();
                            String[] parts = line.split("[: ]+", 3);
                            if (parts.length < 3) {
                                log("Invalid format in: " + file.getName());
                                errorCount++;
                                continue;
                            }

                            String algo = parts[0];
                            String expectedHash = parts[1];
                            String originalFilename = parts[2];

                            File originalFile = new File(file.getParentFile(), originalFilename);
                            if (!originalFile.exists()) {
                                log("❌ Missing file: " + originalFilename);
                                errorCount++;
                                continue;
                            }

                            String actualHash = computeHash(originalFile, algo);
                            if (expectedHash.equalsIgnoreCase(actualHash)) {
                                log("✅ " + originalFilename + " is OK.");
                                okCount++;
                            } else {
                                log("❌ " + originalFilename + " is corrupted or different.");
                                errorCount++;
                            }

                        } catch (Exception ex) {
                            log("❌ Error verifying " + file.getName() + ": " + ex.getMessage());
                            errorCount++;
                        }

                        processed++;
                        publish(processed);
                    }

                    return null;
                }

                @Override
                protected void process(java.util.List<Integer> chunks) {
                    int latest = chunks.get(chunks.size() - 1);
                    progressBar.setValue(latest);
                }

                @Override
                protected void done() {
                    log("✅ Done verifying hashes.");
                    log("Summary: " + totalCount + " files checked — " + okCount + " OK, " + errorCount + " failed.");
                }
            };

            log("Starting hash verification...");
            worker.execute();
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

        // ---------- PROGRESS BAR ----------
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true); // affiche le pourcentage
        progressBar.setMinimum(0);
        progressBar.setMaximum(100);
        progressBar.setValue(0);
        add(progressBar, BorderLayout.SOUTH);
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

    // Get all files with a given extension (e.g. '.mkv') in a folder and its subfolders
    private java.util.List<File> getAllFilesWithExtension(File folder, String extension) {
        java.util.List<File> result = new java.util.ArrayList<>();
        File[] files = folder.listFiles();
        if (files == null) return result;

        for (File file : files) {
            if (file.isDirectory()) {
                result.addAll(getAllFilesWithExtension(file, extension));
            } else if (file.getName().toLowerCase().endsWith(extension.toLowerCase())) {
                result.add(file);
            }
        }

        return result;
    }

    // Get all hash files (.md5,.sha256,...) in a folder and its subfolders
    private java.util.List<File> getAllHashFiles(File folder) {
        java.util.List<File> result = new java.util.ArrayList<>();
        File[] files = folder.listFiles();
        if (files == null) return result;

        for (File file : files) {
            if (file.isDirectory()) {
                result.addAll(getAllHashFiles(file));
            } else if (
                    file.getName().endsWith(".md5") ||
                            file.getName().endsWith(".sha1") ||
                            file.getName().endsWith(".sha256")
            ) {
                result.add(file);
            }
        }

        return result;
    }

}