import javax.swing.*;
import javax.swing.border.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.regex.*;

public class ScanProject {

    private static final List<String> INCLUDED_EXTENSIONS = List.of(
            ".java", ".gradle", ".kt", ".kts", ".xml", ".yml", ".yaml",
            ".properties", ".json", ".md", ".txt", ".zig", ".groovy", ".sql",
            ".js", ".ts", ".html", ".css", ".cs", ".csproj"
    );

    private static final List<String> EXCLUDED_DIRS = List.of(
            ".git", ".gradle", "build", "target", "out", "bin", ".idea", "node_modules"
    );

    private static final Map<String, String> EXT_TO_LANG = Map.ofEntries(
            Map.entry(".java",       "java"),
            Map.entry(".gradle",     "groovy"),
            Map.entry(".kt",         "kotlin"),
            Map.entry(".kts",        "kotlin"),
            Map.entry(".xml",        "xml"),
            Map.entry(".yml",        "yaml"),
            Map.entry(".yaml",       "yaml"),
            Map.entry(".properties", "properties"),
            Map.entry(".json",       "json"),
            Map.entry(".md",         "markdown"),
            Map.entry(".txt",        ""),
            Map.entry(".zig",        "zig"),
            Map.entry(".groovy",     "groovy"),
            Map.entry(".sql",        "sql"),
            Map.entry(".js",         "javascript"),
            Map.entry(".ts",         "typescript"),
            Map.entry(".html",       "html"),
            Map.entry(".css",        "css")
    );

    private static final int MAX_HISTORY = 20;

    private static final List<String> DEFAULT_PATTERNS = List.of(
            ".*\\.java$",
            ".*\\.xml$",
            ".*\\.(java|xml)$",
            ".*\\.(java|kt)$"
    );

    // ── Secret detection patterns ─────────────────────────────────────────────
    // Каждый паттерн: [regex, описание]
    private static final List<String[]> SECRET_PATTERNS = List.of(
            new String[]{ "(?i)(password|passwd|pwd)\\s*[=:]\\s*\\S+",          "Password" },
            new String[]{ "(?i)(secret|secret_key|secretkey)\\s*[=:]\\s*\\S+",  "Secret key" },
            new String[]{ "(?i)(api_key|apikey|api-key)\\s*[=:]\\s*\\S+",       "API key" },
            new String[]{ "(?i)(token|auth_token|access_token)\\s*[=:]\\s*\\S+","Token" },
            new String[]{ "AKIA[0-9A-Z]{16}",                                    "AWS Access Key ID" },
            new String[]{ "(?i)aws_secret_access_key\\s*[=:]\\s*\\S+",          "AWS Secret Access Key" },
            new String[]{ "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY",    "Private key" },
            new String[]{ "(?i)(database_url|db_url|jdbc:).*@[\\w.]+",          "Database URL with credentials" },
            new String[]{ "(?i)(private_key|private-key)\\s*[=:]\\s*\\S+",      "Private key value" },
            new String[]{ "ghp_[0-9a-zA-Z]{36}",                                "GitHub Personal Access Token" },
            new String[]{ "xox[bpoas]-[0-9a-zA-Z\\-]+",                         "Slack token" },
            new String[]{ "(?i)\\.env(\\.local|\\.prod|\\.production)?$",        "Env file" }
    );

    // Компилируем паттерны один раз
    private static final List<Pattern> COMPILED_SECRETS = SECRET_PATTERNS.stream()
            .map(p -> Pattern.compile(p[0]))
            .toList();

    // ── entry point ───────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        String projectRoot = ".";
        boolean useUi = false;
        boolean ignoreSecrets = false;

        for (String arg : args) {
            if ("-ui".equalsIgnoreCase(arg))             useUi = true;
            else if ("-is".equalsIgnoreCase(arg)) ignoreSecrets = true;
            else                                          projectRoot = arg;
        }
        Path root = Paths.get(projectRoot).toAbsolutePath().normalize();

        if (useUi) {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            boolean finalIgnoreSecrets = ignoreSecrets;
            Path finalRoot = root;
            SwingUtilities.invokeLater(() -> new ScanUi(finalRoot, finalIgnoreSecrets).show());
        } else {
            long t0 = System.currentTimeMillis();
            List<Path> files = collectFiles(root);
            String out = buildOutputName(root);

            SecretScanResult secretResult = ignoreSecrets
                    ? new SecretScanResult(files, List.of())
                    : scanForSecrets(root, files);

            writeMarkdown(root, secretResult.safeFiles(), out);

            long dt = System.currentTimeMillis() - t0;
            System.out.printf("Done! %d files → %s  (%.1f s)%n",
                    secretResult.safeFiles().size(), out, dt / 1000.0);

            if (!secretResult.secretFiles().isEmpty()) {
                System.out.println();
                System.out.println("⚠️  WARNING: The following files were excluded because they may contain secrets:");
                for (SecretFile sf : secretResult.secretFiles()) {
                    System.out.printf("   • %s  [%s]%n",
                            root.relativize(sf.path()).toString().replace('\\', '/'),
                            sf.reason());
                }
                System.out.println();
                System.out.println("Use -ignore-secrets to include them anyway.");
            }
        }
    }

    // ── Secret scanning ───────────────────────────────────────────────────────

    record SecretFile(Path path, String reason) {}

    record SecretScanResult(List<Path> safeFiles, List<SecretFile> secretFiles) {}

    static SecretScanResult scanForSecrets(Path root, List<Path> files) {
        List<Path>       safe    = new ArrayList<>();
        List<SecretFile> secrets = new ArrayList<>();

        for (Path file : files) {
            String rel = root.relativize(file).toString().replace('\\', '/');
            String foundReason = null;

            // Сначала проверяем имя файла (для .env и подобных)
            for (int i = 0; i < COMPILED_SECRETS.size(); i++) {
                if (COMPILED_SECRETS.get(i).matcher(rel).find()) {
                    foundReason = SECRET_PATTERNS.get(i)[1];
                    break;
                }
            }

            // Затем проверяем содержимое
            if (foundReason == null) {
                try {
                    String content = Files.readString(file, StandardCharsets.UTF_8);
                    for (int i = 0; i < COMPILED_SECRETS.size(); i++) {
                        Matcher m = COMPILED_SECRETS.get(i).matcher(content);
                        if (m.find()) {
                            foundReason = SECRET_PATTERNS.get(i)[1];
                            break;
                        }
                    }
                } catch (IOException ignored) {}
            }

            if (foundReason != null) secrets.add(new SecretFile(file, foundReason));
            else                     safe.add(file);
        }
        return new SecretScanResult(safe, secrets);
    }

    // ── History ───────────────────────────────────────────────────────────────

    static Path historyFile(Path root) {
        Path dir = Paths.get(System.getProperty("user.home"), ".scanproject");
        try { Files.createDirectories(dir); } catch (IOException ignored) {}
        return dir.resolve(root.getFileName() + "_history");
    }

    static List<String> loadHistory(Path root) {
        List<String> list = new ArrayList<>();
        Path f = historyFile(root);
        if (Files.exists(f)) {
            try { list.addAll(Files.readAllLines(f)); } catch (IOException ignored) {}
        }
        for (String p : DEFAULT_PATTERNS)
            if (!list.contains(p)) list.add(p);
        return list;
    }

    static void saveHistory(Path root, List<String> history) {
        try { Files.write(historyFile(root), history); } catch (IOException ignored) {}
    }

    // ── UI ────────────────────────────────────────────────────────────────────

    static class ScanUi {
        final Path root;
        final boolean ignoreSecretsDefault;
        CheckboxTreeNode treeRoot;
        DefaultTreeModel treeModel;
        JTree tree;
        JComboBox<String> regexBox;
        JLabel statusLabel;
        JCheckBox ignoreSecretsBox;
        List<String> history;

        ScanUi(Path root, boolean ignoreSecretsDefault) {
            this.root = root;
            this.ignoreSecretsDefault = ignoreSecretsDefault;
        }

        void show() {
            history = loadHistory(root);

            JFrame frame = new JFrame("Select Files to Send to Perplexity");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(580, 700);
            frame.setLocationRelativeTo(null);

            JLabel loading = new JLabel("Scanning...", SwingConstants.CENTER);
            loading.setFont(loading.getFont().deriveFont(Font.ITALIC, 14f));
            frame.setLayout(new BorderLayout());
            frame.add(loading, BorderLayout.CENTER);
            frame.setVisible(true);

            SwingWorker<CheckboxTreeNode, Void> scanner = new SwingWorker<>() {
                @Override protected CheckboxTreeNode doInBackground() {
                    return buildTree(root, root);
                }
                @Override protected void done() {
                    try {
                        treeRoot = get();
                        setAllChecked(treeRoot, false);
                        frame.getContentPane().removeAll();
                        frame.setLayout(new BorderLayout(0, 4));
                        buildUi(frame);
                        frame.revalidate();
                        frame.repaint();
                    } catch (Exception ex) { ex.printStackTrace(); }
                }
            };
            scanner.execute();
        }

        void buildUi(JFrame frame) {
            // ── regex panel ──
            regexBox = new JComboBox<>();
            regexBox.setEditable(true);
            regexBox.setPrototypeDisplayValue(".*\\.java$_____________________");
            history.forEach(regexBox::addItem);
            regexBox.setSelectedIndex(-1);
            ((JTextField) regexBox.getEditor().getEditorComponent()).setText("");

            JButton applyBtn = new JButton("Apply");
            JButton clearBtn = new JButton("Clear");
            JButton helpBtn  = new JButton("?");
            helpBtn.setMargin(new Insets(2, 6, 2, 6));

            applyBtn.addActionListener(e -> applyRegex());
            clearBtn.addActionListener(e -> clearRegex());
            helpBtn .addActionListener(e -> showHelp(frame));
            ((JTextField) regexBox.getEditor().getEditorComponent())
                    .addKeyListener(new KeyAdapter() {
                        @Override public void keyPressed(KeyEvent e) {
                            if (e.getKeyCode() == KeyEvent.VK_ENTER) applyRegex();
                        }
                    });

            JPanel regexPanel = new JPanel(new GridBagLayout());
            regexPanel.setBorder(new EmptyBorder(6, 8, 4, 8));
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(0, 2, 0, 2);
            gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
            regexPanel.add(new JLabel("Filter by regex:"), gbc);
            gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
            regexPanel.add(regexBox, gbc);
            gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
            regexPanel.add(applyBtn, gbc);
            gbc.gridx = 3; regexPanel.add(clearBtn, gbc);
            gbc.gridx = 4; regexPanel.add(helpBtn,  gbc);

            // ── tree ──
            treeModel = new DefaultTreeModel(treeRoot);
            tree      = new JTree(treeModel);
            tree.setRootVisible(true);
            tree.setCellRenderer(new CheckboxTreeCellRenderer());
            tree.addMouseListener(new CheckboxMouseListener(tree, this::updateStatus));
            tree.expandRow(0);

            JScrollPane scroll = new JScrollPane(tree);
            scroll.setBorder(new CompoundBorder(
                    new EmptyBorder(0, 8, 0, 8),
                    new LineBorder(Color.LIGHT_GRAY, 1)));

            // ── bottom panel ──
            statusLabel = new JLabel("No files selected");
            statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 12f));
            statusLabel.setForeground(Color.GRAY);

            ignoreSecretsBox = new JCheckBox("Ignore secrets check");
            ignoreSecretsBox.setSelected(ignoreSecretsDefault);
            ignoreSecretsBox.setFont(ignoreSecretsBox.getFont().deriveFont(Font.PLAIN, 12f));
            ignoreSecretsBox.setToolTipText("Include files even if they may contain secrets");

            JPanel statusRow = new JPanel(new BorderLayout(8, 0));
            statusRow.setBorder(new EmptyBorder(4, 10, 0, 10));
            statusRow.add(statusLabel,    BorderLayout.WEST);
            statusRow.add(ignoreSecretsBox, BorderLayout.EAST);

            JButton okBtn     = new JButton("OK");
            JButton cancelBtn = new JButton("Cancel");
            okBtn    .setPreferredSize(new Dimension(90, 30));
            cancelBtn.setPreferredSize(new Dimension(90, 30));

            okBtn.addActionListener(e -> generate(frame, okBtn));
            cancelBtn.addActionListener(e -> frame.dispose());

            JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            btnRow.add(okBtn);
            btnRow.add(cancelBtn);

            JPanel bottomPanel = new JPanel(new BorderLayout());
            bottomPanel.setBorder(new EmptyBorder(0, 0, 8, 8));
            bottomPanel.add(statusRow, BorderLayout.NORTH);
            bottomPanel.add(btnRow,    BorderLayout.SOUTH);

            frame.add(regexPanel,  BorderLayout.NORTH);
            frame.add(scroll,      BorderLayout.CENTER);
            frame.add(bottomPanel, BorderLayout.SOUTH);
            frame.getRootPane().setDefaultButton(okBtn);
        }

        void generate(JFrame frame, JButton okBtn) {
            List<Path> selected = collectChecked(treeRoot);
            if (selected.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Не выбрано ни одного файла.",
                        "Пусто", JOptionPane.WARNING_MESSAGE);
                return;
            }
            okBtn.setEnabled(false);
            okBtn.setText("Writing...");
            boolean skipSecrets = !ignoreSecretsBox.isSelected();

            SwingWorker<GenerateResult, Void> writer = new SwingWorker<>() {
                @Override protected GenerateResult doInBackground() throws Exception {
                    List<Path> toWrite;
                    List<SecretFile> foundSecrets;

                    if (skipSecrets) {
                        SecretScanResult result = scanForSecrets(root, selected);
                        toWrite      = result.safeFiles();
                        foundSecrets = result.secretFiles();
                    } else {
                        toWrite      = selected;
                        foundSecrets = List.of();
                    }

                    String outFile = buildOutputName(root);
                    writeMarkdown(root, toWrite, outFile);
                    return new GenerateResult(outFile, toWrite.size(), foundSecrets);
                }

                @Override protected void done() {
                    try {
                        GenerateResult r = get();
                        StringBuilder msg = new StringBuilder();
                        msg.append("Готово!\n")
                                .append(r.outFile()).append("\n")
                                .append("(").append(r.fileCount()).append(" файлов)");

                        if (!r.secretFiles().isEmpty()) {
                            msg.append("\n\n⚠️ Исключены (содержат секреты):");
                            for (SecretFile sf : r.secretFiles()) {
                                msg.append("\n  • ")
                                        .append(root.relativize(sf.path()).toString().replace('\\', '/'))
                                        .append("  [").append(sf.reason()).append("]");
                            }
                        }

                        int msgType = r.secretFiles().isEmpty()
                                ? JOptionPane.INFORMATION_MESSAGE
                                : JOptionPane.WARNING_MESSAGE;

                        JOptionPane.showMessageDialog(frame, msg.toString(),
                                r.secretFiles().isEmpty() ? "Успех" : "Успех (с предупреждениями)",
                                msgType);
                        frame.dispose();
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(frame, "Ошибка: " + ex.getMessage(),
                                "Ошибка", JOptionPane.ERROR_MESSAGE);
                        okBtn.setEnabled(true);
                        okBtn.setText("OK");
                    }
                }
            };
            writer.execute();
        }

        // ── regex ─────────────────────────────────────────────────────────────

        void applyRegex() {
            String pattern = ((JTextField) regexBox.getEditor().getEditorComponent()).getText().trim();
            if (pattern.isEmpty()) { clearRegex(); return; }
            Pattern p;
            try { p = Pattern.compile(pattern); }
            catch (PatternSyntaxException ex) {
                statusLabel.setText("✗ Invalid regex: " + ex.getDescription());
                statusLabel.setForeground(Color.RED);
                return;
            }
            setAllChecked(treeRoot, false);
            int count = applyPatternToNode(treeRoot, p);
            propagateAllUp(treeRoot);
            treeModel.reload();
            expandMatchedFolders(treeRoot, new TreePath(treeRoot));
            statusLabel.setText("✓ Selected " + count + " files matching pattern");
            statusLabel.setForeground(new Color(0, 120, 0));
            history.remove(pattern);
            history.add(0, pattern);
            for (String def : DEFAULT_PATTERNS)
                if (!history.contains(def)) history.add(def);
            if (history.size() > MAX_HISTORY)
                history = new ArrayList<>(history.subList(0, MAX_HISTORY));
            saveHistory(root, history);
            regexBox.removeAllItems();
            history.forEach(regexBox::addItem);
            regexBox.setSelectedItem(pattern);
        }

        int applyPatternToNode(CheckboxTreeNode node, Pattern p) {
            int count = 0;
            Enumeration<?> e = node.depthFirstEnumeration();
            while (e.hasMoreElements()) {
                CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
                if (n.isFile) {
                    String rel = root.relativize(n.path).toString().replace('\\', '/');
                    if (p.matcher(rel).find()) { n.checked = true; count++; }
                }
            }
            return count;
        }

        void expandMatchedFolders(CheckboxTreeNode node, TreePath path) {
            if (node.isFile) return;
            if (hasCheckedDescendant(node)) tree.expandPath(path);
            Enumeration<?> e = node.children();
            while (e.hasMoreElements()) {
                CheckboxTreeNode ch = (CheckboxTreeNode) e.nextElement();
                expandMatchedFolders(ch, path.pathByAddingChild(ch));
            }
        }

        boolean hasCheckedDescendant(CheckboxTreeNode node) {
            Enumeration<?> e = node.depthFirstEnumeration();
            while (e.hasMoreElements()) {
                CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
                if (n.isFile && n.checked) return true;
            }
            return false;
        }

        void clearRegex() {
            ((JTextField) regexBox.getEditor().getEditorComponent()).setText("");
            regexBox.setSelectedIndex(-1);
            setAllChecked(treeRoot, false);
            propagateAllUp(treeRoot);
            treeModel.reload();
            tree.collapseRow(0);
            tree.expandRow(0);
            updateStatus();
        }

        void updateStatus() {
            if (statusLabel == null) return;
            int count = collectChecked(treeRoot).size();
            if (count == 0) {
                statusLabel.setText("No files selected");
                statusLabel.setForeground(Color.GRAY);
            } else {
                statusLabel.setText("✓ Selected " + count + " files");
                statusLabel.setForeground(new Color(0, 100, 0));
            }
        }

        void showHelp(JFrame parent) {
            JOptionPane.showMessageDialog(parent,
                    "Regex applied to relative file paths.\n\nExamples:\n" +
                            "  .*\\.java$             — all Java files\n" +
                            "  .*\\.xml$              — all XML files\n" +
                            "  .*\\.(java|xml)$       — Java and XML\n" +
                            "  .*\\.(java|kt)$        — Java and Kotlin\n" +
                            "  src/main/.*\\.java     — only in src/main\n\n" +
                            "Secret check scans file names and content for:\n" +
                            "passwords, API keys, tokens, private keys, AWS credentials, etc.\n" +
                            "Use 'Ignore secrets check' to bypass.",
                    "Help", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    // ── GenerateResult ────────────────────────────────────────────────────────

    record GenerateResult(String outFile, int fileCount, List<SecretFile> secretFiles) {}

    // ── CheckboxTreeNode ──────────────────────────────────────────────────────

    static class CheckboxTreeNode extends DefaultMutableTreeNode {
        boolean checked = false;
        final boolean isFile;
        final Path path;

        CheckboxTreeNode(Path path, boolean isFile, String label) {
            super(label);
            this.path   = path;
            this.isFile = isFile;
        }
    }

    static CheckboxTreeNode buildTree(Path root, Path dir) {
        String label = dir.equals(root)
                ? root.getFileName().toString()
                : dir.getFileName().toString() + " [dir]";
        CheckboxTreeNode node = new CheckboxTreeNode(dir, false, label);
        List<Path> dirs  = new ArrayList<>();
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            for (Path entry : ds) {
                if (Files.isDirectory(entry)) {
                    if (!EXCLUDED_DIRS.contains(entry.getFileName().toString())) dirs.add(entry);
                } else {
                    if (isIncludedFile(entry)) files.add(entry);
                }
            }
        } catch (IOException ignored) {}
        dirs .sort(Comparator.naturalOrder());
        files.sort(Comparator.naturalOrder());
        for (Path d : dirs)  node.add(buildTree(root, d));
        for (Path f : files) node.add(new CheckboxTreeNode(f, true, f.getFileName().toString()));
        return node;
    }

    static List<Path> collectChecked(CheckboxTreeNode root) {
        List<Path> result = new ArrayList<>();
        Enumeration<?> e = root.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
            if (n.isFile && n.checked) result.add(n.path);
        }
        result.sort(Comparator.naturalOrder());
        return result;
    }

    static void setAllChecked(CheckboxTreeNode root, boolean val) {
        Enumeration<?> e = root.depthFirstEnumeration();
        while (e.hasMoreElements()) ((CheckboxTreeNode) e.nextElement()).checked = val;
    }

    static void propagateAllUp(CheckboxTreeNode root) {
        Enumeration<?> e = root.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
            if (!n.isFile && n.getChildCount() > 0) {
                Enumeration<?> ch = n.children();
                boolean any = false;
                while (ch.hasMoreElements())
                    if (((CheckboxTreeNode) ch.nextElement()).checked) { any = true; break; }
                n.checked = any;
            }
        }
    }

    // ── Renderer ──────────────────────────────────────────────────────────────

    static class CheckboxTreeCellRenderer extends DefaultTreeCellRenderer {
        private final JCheckBox checkbox = new JCheckBox();
        private final JPanel    panel    = new JPanel(new BorderLayout(4, 0));

        CheckboxTreeCellRenderer() { checkbox.setOpaque(false); panel.setOpaque(true); }

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value,
                                                      boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            if (!(value instanceof CheckboxTreeNode n)) return this;
            checkbox.setSelected(n.checked);
            checkbox.setText(n.getUserObject().toString());
            checkbox.setFont(tree.getFont());
            checkbox.setForeground(sel ? getTextSelectionColor() : getTextNonSelectionColor());
            panel.removeAll();
            panel.setBackground(sel ? getBackgroundSelectionColor() : getBackgroundNonSelectionColor());
            panel.add(checkbox, BorderLayout.CENTER);
            return panel;
        }
    }

    // ── Mouse listener ────────────────────────────────────────────────────────

    static class CheckboxMouseListener extends MouseAdapter {
        private final JTree tree;
        private final Runnable onChanged;

        CheckboxMouseListener(JTree tree, Runnable onChanged) {
            this.tree = tree; this.onChanged = onChanged;
        }

        @Override public void mouseClicked(MouseEvent e) {
            int row = tree.getRowForLocation(e.getX(), e.getY());
            if (row < 0) return;
            TreePath tp = tree.getPathForRow(row);
            if (!(tp.getLastPathComponent() instanceof CheckboxTreeNode n)) return;
            n.checked = !n.checked;
            if (!n.isFile) cascadeDown(n, n.checked);
            propagateUp(n);
            tree.repaint();
            onChanged.run();
        }

        private void cascadeDown(CheckboxTreeNode node, boolean val) {
            Enumeration<?> e = node.children();
            while (e.hasMoreElements()) {
                CheckboxTreeNode ch = (CheckboxTreeNode) e.nextElement();
                ch.checked = val;
                if (!ch.isFile) cascadeDown(ch, val);
            }
        }

        private void propagateUp(CheckboxTreeNode node) {
            CheckboxTreeNode parent = (CheckboxTreeNode) node.getParent();
            if (parent == null) return;
            Enumeration<?> e = parent.children();
            boolean any = false;
            while (e.hasMoreElements())
                if (((CheckboxTreeNode) e.nextElement()).checked) { any = true; break; }
            parent.checked = any;
            propagateUp(parent);
        }
    }

    // ── File I/O ──────────────────────────────────────────────────────────────

    static List<Path> collectFiles(Path root) throws IOException {
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes a) {
                return EXCLUDED_DIRS.contains(dir.getFileName().toString())
                        ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes a) {
                if (isIncludedFile(file)) files.add(file);
                return FileVisitResult.CONTINUE;
            }
        });
        files.sort(Comparator.naturalOrder());
        return files;
    }

    static String buildOutputName(Path root) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy_MM_dd_HH_mm"));
        return root.getFileName() + "_" + ts + ".md";
    }

    static void writeMarkdown(Path root, List<Path> files, String outputFile) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8),
                256 * 1024);
             PrintWriter w = new PrintWriter(bw)) {

            w.println("# Project: " + root.getFileName());
            w.println();
            w.println("> Generated: " + LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
            w.println();
            w.println("## Project Structure");
            w.println();
            w.println("```");
            writeTree(w, root, files);
            w.println("```");
            w.println();
            w.println("## Source Code");
            w.println();
            for (Path f : files) {
                String rel  = root.relativize(f).toString().replace('\\', '/');
                String lang = getLang(f);
                w.println("### `" + rel + "`");
                w.println();
                w.println("```" + lang);
                try {
                    String content = Files.readString(f, StandardCharsets.UTF_8);
                    w.print(content);
                    if (!content.isEmpty() && content.charAt(content.length() - 1) != '\n')
                        w.println();
                } catch (IOException e) {
                    w.println("// ERROR READING FILE: " + e.getMessage());
                }
                w.println("```");
                w.println();
            }
        }
    }

    static void writeTree(PrintWriter w, Path root, List<Path> files) {
        w.println(root.getFileName() + "/");
        TreeMapNode treeMap = new TreeMapNode();
        for (Path f : files) treeMap.insert(root.relativize(f));
        treeMap.print(w, "");
    }

    static class TreeMapNode {
        final Map<String, TreeMapNode> dirs  = new LinkedHashMap<>();
        final List<String>             files = new ArrayList<>();

        void insert(Path rel) {
            if (rel.getNameCount() == 1) files.add(rel.getFileName().toString());
            else {
                String head = rel.getName(0).toString();
                dirs.computeIfAbsent(head, k -> new TreeMapNode())
                        .insert(rel.subpath(1, rel.getNameCount()));
            }
        }

        void print(PrintWriter w, String prefix) {
            int total = dirs.size() + files.size();
            int idx   = 0;
            for (Map.Entry<String, TreeMapNode> e : dirs.entrySet()) {
                boolean last = (++idx == total);
                w.println(prefix + (last ? "└── " : "├── ") + e.getKey() + "/");
                e.getValue().print(w, prefix + (last ? "    " : "│   "));
            }
            for (String file : files) {
                boolean last = (++idx == total);
                w.println(prefix + (last ? "└── " : "├── ") + file);
            }
        }
    }

    static String getLang(Path file) {
        String name = file.getFileName().toString().toLowerCase();
        return EXT_TO_LANG.entrySet().stream()
                .filter(e -> name.endsWith(e.getKey()))
                .map(Map.Entry::getValue)
                .findFirst().orElse("");
    }

    static boolean isIncludedFile(Path file) {
        String name = file.getFileName().toString().toLowerCase();
        return INCLUDED_EXTENSIONS.stream().anyMatch(name::endsWith);
    }
}
