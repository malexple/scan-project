/*
 * ScanProject — single-file project scanner for AI context
 * Copyright (c) 2026 malexple
 * Licensed under the MIT License
 */
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.regex.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ScanProject {

    private static final List<String> INCLUDED_EXTENSIONS = List.of(
            ".java", ".gradle", ".kt", ".kts", ".xml", ".yml", ".yaml",
            ".properties", ".json", ".md", ".txt", ".zig", ".groovy", ".sql",
            ".js", ".ts", ".html", ".css", ".cs", ".csproj"
    );

    // ── Имя выходного MD: ЕДИНСТВЕННАЯ точка определения ─────────────────────
    // Формат метки времени в имени файла
    private static final String OUTPUT_TS_FORMAT = "yyyy_MM_dd_HH_mm";
    // Шаблон полного имени: %1$s = имя проекта, %2$s = метка времени
    private static final String OUTPUT_NAME_FORMAT = "%1$s_%2$s.md";
    // Распознаватель сгенерированных файлов (чтобы не сканировать их самих).
    // Строится из двух констант выше автоматически — руками править не нужно:
    // поменяли формат или шаблон → regex пересобрался сам.
    private static final Pattern GENERATED_MD = Pattern.compile(
            OUTPUT_NAME_FORMAT.replace(".", "\\.")
                    .replace("%1$s", ".+")
                    .replace("%2$s", tsFormatToRegex(OUTPUT_TS_FORMAT)));

    /** Regex-двойник формата времени: "yyyy_MM_dd_HH_mm" → "\d{4}_\d{2}_\d{2}_\d{2}_\d{2}".
     *  Буквенные поля (y, M, d, H, m, s…) трактуем как цифры, разделители экранируются. */
    private static String tsFormatToRegex(String format) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < format.length()) {
            char c = format.charAt(i);
            if (Character.isLetter(c)) {
                int j = i;
                while (j < format.length() && format.charAt(j) == c) j++;
                sb.append("\\d{").append(j - i).append('}');
                i = j;
            } else {
                sb.append(Pattern.quote(String.valueOf(c)));
                i++;
            }
        }
        return sb.toString();
    }


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

    private static final List<Pattern> COMPILED_SECRETS = SECRET_PATTERNS.stream()
            .map(p -> Pattern.compile(p[0]))
            .toList();

    private static ClassLoader flatLafLoader;

    // ── Диагностика запуска ─────────────────────────────────────────────────
    private static final long START_MS = System.currentTimeMillis();
    private static final AtomicInteger SCAN_DIRS  = new AtomicInteger();
    private static final AtomicInteger SCAN_FILES = new AtomicInteger();

    static void log(String msg) {
        System.out.printf("[%4.1fs] %s%n", (System.currentTimeMillis() - START_MS) / 1000.0, msg);
    }

    // ── Прогрев UI-классов в фоне (EDT не тормозит при создании компонентов) ──
    private static final java.util.concurrent.CountDownLatch uiWarm = new java.util.concurrent.CountDownLatch(1);

    static void startUiWarmup() {
        Thread t = new Thread(() -> {
            try {
                ClassLoader cl = flatLafLoader != null ? flatLafLoader : ScanProject.class.getClassLoader();
                String[] classes = {
                        "com.formdev.flatlaf.ui.FlatButtonUI",
                        "com.formdev.flatlaf.ui.FlatLabelUI",
                        "com.formdev.flatlaf.ui.FlatTextFieldUI",
                        "com.formdev.flatlaf.ui.FlatComboBoxUI",
                        "com.formdev.flatlaf.ui.FlatCheckBoxUI",
                        "com.formdev.flatlaf.ui.FlatTreeUI",
                        "com.formdev.flatlaf.ui.FlatScrollPaneUI",
                        "com.formdev.flatlaf.ui.FlatRootPaneUI",
                        "com.formdev.flatlaf.ui.FlatOptionPaneUI",
                        "javax.swing.plaf.basic.BasicTreeUI",
                        "javax.swing.plaf.basic.BasicComboBoxUI",
                };
                for (String cn : classes) {
                    try { Class.forName(cn, true, cl); } catch (Throwable ignored) {}
                }
                BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB);
                Graphics2D g = img.createGraphics();
                g.getFontMetrics(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
                g.dispose();
                log("warmup: UI classes & fonts preloaded");
            } finally {
                uiWarm.countDown();
            }
        }, "ui-warmup");
        t.setDaemon(true);
        t.start();
    }

    // ── Индекс проекта (кэш структуры для мгновенного старта) ─────────────────

    record IndexData(CheckboxTreeNode root, Map<String, Long> dirMtimes) {}

    static Path indexFile(Path root) {
        Path dir = Paths.get(System.getProperty("user.home"), ".scanproject");
        try { Files.createDirectories(dir); } catch (IOException ignored) {}
        return dir.resolve(root.getFileName() + "_index");
    }

    static void saveIndex(Path root, CheckboxTreeNode node, List<String> lines) {
        try {
            long mt = Files.getLastModifiedTime(node.path).toMillis();
            String rel = node.path.equals(root) ? "" : root.relativize(node.path).toString().replace('\\', '/');
            if (!node.isFile) {
                lines.add("D\t" + rel + "\t" + mt);
                Enumeration<?> e = node.children();
                while (e.hasMoreElements()) saveIndex(root, (CheckboxTreeNode) e.nextElement(), lines);
            } else {
                lines.add("F\t" + rel + "\t" + mt);
            }
        } catch (IOException ignored) {}
    }

    static void saveIndex(Path root, CheckboxTreeNode treeRoot) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("v2");
        saveIndex(root, treeRoot, lines);
        Files.write(indexFile(root), lines, StandardCharsets.UTF_8);
    }

    static IndexData loadIndex(Path root) {
        Path f = indexFile(root);
        if (!Files.isRegularFile(f)) return null;
        try {
            List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
            if (lines.isEmpty() || !"v2".equals(lines.get(0))) return null;
            CheckboxTreeNode rootNode = null;
            Map<String, CheckboxTreeNode> dirs = new HashMap<>();
            Map<String, Long> mtimes = new HashMap<>();
            for (int i = 1; i < lines.size(); i++) {
                String[] p = lines.get(i).split("\t");
                if (p.length < 3) continue;
                String kind = p[0];
                String rel = p[1];
                long mt;
                try { mt = Long.parseLong(p[2]); } catch (NumberFormatException ex) { continue; }
                if ("D".equals(kind)) {
                    Path dirPath = rel.isEmpty() ? root : root.resolve(rel);
                    String label = rel.isEmpty()
                            ? root.getFileName().toString()
                            : dirPath.getFileName().toString() + " [dir]";
                    CheckboxTreeNode n = new CheckboxTreeNode(dirPath, false, label);
                    if (rel.isEmpty()) {
                        rootNode = n;
                    } else {
                        String parentRel = rel.contains("/") ? rel.substring(0, rel.lastIndexOf('/')) : "";
                        CheckboxTreeNode parent = dirs.get(parentRel);
                        if (parent == null) continue;
                        parent.add(n);
                    }
                    dirs.put(rel, n);
                    mtimes.put(rel, mt);
                } else if ("F".equals(kind)) {
                    String parentRel = rel.contains("/") ? rel.substring(0, rel.lastIndexOf('/')) : "";
                    CheckboxTreeNode parent = dirs.get(parentRel);
                    if (parent == null) continue;
                    parent.add(new CheckboxTreeNode(root.resolve(rel), true,
                            rel.substring(rel.lastIndexOf('/') + 1)));
                }
            }
            if (rootNode == null) return null;
            sortChildren(rootNode);
            return new IndexData(rootNode, mtimes);
        } catch (Exception e) {
            return null;
        }
    }

    static void sortChildren(CheckboxTreeNode node) {
        List<TreeNode> kids = new ArrayList<>();
        Enumeration<?> e = node.children();
        while (e.hasMoreElements()) kids.add((TreeNode) e.nextElement());
        node.removeAllChildren();
        kids.sort(Comparator
                .comparingInt((TreeNode o) -> ((CheckboxTreeNode) o).isFile ? 1 : 0)
                .thenComparing(o -> ((CheckboxTreeNode) o).path));
        for (TreeNode k : kids) node.add((MutableTreeNode) k);
        for (TreeNode k : kids) {
            if (!((CheckboxTreeNode) k).isFile) sortChildren((CheckboxTreeNode) k);
        }
    }

    static boolean indexFresh(Path root, Map<String, Long> dirMtimes) {
        for (Map.Entry<String, Long> en : dirMtimes.entrySet()) {
            Path d = en.getKey().isEmpty() ? root : root.resolve(en.getKey());
            try {
                if (Files.getLastModifiedTime(d).toMillis() != en.getValue()) return false;
            } catch (IOException e) {
                return false;
            }
        }
        return true;
    }

    // ── entry point ───────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "-unpack".equalsIgnoreCase(args[0])) {
            if (args.length < 2) {
                System.out.println("Использование: java ScanProject.java -unpack <файл.md> [целевая_директория]");
                return;
            }
            String mdFile = args[1];
            String targetDir = args.length >= 3 ? args[2] : ".";
            unpackMarkdown(mdFile, targetDir);
            return;
        }

        String projectRoot = ".";
        boolean useUi = false;
        boolean ignoreSecrets = false;
        String lafJar = null;
        String theme = "dark";

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("-ui".equalsIgnoreCase(arg))                          useUi = true;
            else if ("-is".equalsIgnoreCase(arg))                     ignoreSecrets = true;
            else if ("-laf".equalsIgnoreCase(arg) && i + 1 < args.length)   lafJar = args[++i];
            else if ("-theme".equalsIgnoreCase(arg) && i + 1 < args.length) theme = args[++i];
            else                                                      projectRoot = arg;
        }
        Path root = Paths.get(projectRoot).toAbsolutePath().normalize();

        if (useUi) {
            log("main: args parsed, UI mode");
            boolean dark = !"light".equalsIgnoreCase(theme);
            if (!setupFlatLaf(lafJar, dark)) {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            }
            log("main: look-and-feel ready");
            startUiWarmup();
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
                System.out.println("Use -is to include them anyway.");
            }
        }
    }

    // ── FlatLaf ───────────────────────────────────────────────────────────────

    static boolean setupFlatLaf(String explicitJar, boolean dark) {
        String cls = "com.formdev.flatlaf." + (dark ? "FlatDarkLaf" : "FlatLightLaf");

        try {
            Class<?> c = Class.forName(cls);
            if (applyLaf(c)) {
                System.out.println("🎨 FlatLaf (" + (dark ? "dark" : "light") + ") применен из classpath.");
                return true;
            }
        } catch (Throwable ignored) {}

        List<Path> candidates = new ArrayList<>();
        if (explicitJar != null) candidates.add(Paths.get(explicitJar).toAbsolutePath().normalize());
        String prop = System.getProperty("flatlaf.jar");
        if (prop != null) candidates.add(Paths.get(prop).toAbsolutePath().normalize());
        Path found = findFlatLafJar();
        if (found != null) candidates.add(found);

        for (Path jar : candidates) {
            if (!Files.isRegularFile(jar)) {
                if (explicitJar != null && jar.equals(candidates.get(0)))
                    System.out.println("⚠️ FlatLaf jar не найден по пути: " + jar);
                continue;
            }
            try {
                URLClassLoader cl = new URLClassLoader(
                        new URL[]{ jar.toUri().toURL() },
                        ScanProject.class.getClassLoader());
                flatLafLoader = cl;
                Class<?> c = Class.forName(cls, true, cl);
                if (applyLaf(c)) {
                    System.out.println("🎨 FlatLaf (" + (dark ? "dark" : "light") + ") применен: " + jar);
                    return true;
                }
            } catch (Throwable t) {
                System.out.println("⚠️ Не удалось загрузить FlatLaf из " + jar + ": " + t);
            }
        }

        System.out.println("⚠️ FlatLaf не найден. Используется системная тема.");
        return false;
    }

    static boolean applyLaf(Class<?> c) {
        boolean ok = false;
        try { c.getMethod("setup").invoke(null); ok = true; }
        catch (Throwable ignored) {}
        if (!ok) {
            try { UIManager.setLookAndFeel((LookAndFeel) c.getDeclaredConstructor().newInstance()); ok = true; }
            catch (Throwable ignored) {}
        }
        return ok;
    }

    static Path findFlatLafJar() {
        Path cwd = Paths.get("").toAbsolutePath().normalize();
        List<Path> searchDirs = List.of(cwd, cwd.resolve("..").normalize(), cwd.resolve("../..").normalize());
        for (Path dir : searchDirs) {
            if (!Files.isDirectory(dir)) continue;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "flatlaf*.jar")) {
                for (Path p : ds) return p.toAbsolutePath().normalize();
            } catch (IOException ignored) {}
        }
        return null;
    }

    // ── Unpacker ──────────────────────────────────────────────────────────────

    static void unpackMarkdown(String mdFilePath, String targetDirPath) throws IOException {
        Path mdPath = Paths.get(mdFilePath).toAbsolutePath().normalize();
        Path targetDir = Paths.get(targetDirPath).toAbsolutePath().normalize();

        if (!Files.exists(mdPath)) {
            System.err.println("❌ Markdown файл не найден: " + mdPath);
            return;
        }

        List<String> lines = Files.readAllLines(mdPath, StandardCharsets.UTF_8);

        String currentFile = null;
        StringBuilder content = new StringBuilder();
        boolean inCodeBlock = false;
        int filesExtracted = 0;

        for (String line : lines) {
            if (line.startsWith("### `") && line.endsWith("`")) {
                currentFile = line.substring(5, line.length() - 1);
                continue;
            }

            if (line.startsWith("```") && currentFile != null && !inCodeBlock) {
                inCodeBlock = true;
                content.setLength(0);
                continue;
            }

            if (line.trim().equals("```") && inCodeBlock) {
                inCodeBlock = false;
                if (currentFile != null) {
                    Path outFile = targetDir.resolve(currentFile).normalize();
                    if (!outFile.startsWith(targetDir)) {
                        System.err.println("⚠️ Пропущен небезопасный путь: " + currentFile);
                    } else {
                        Files.createDirectories(outFile.getParent());
                        Files.writeString(outFile, content.toString(), StandardCharsets.UTF_8);
                        filesExtracted++;
                        System.out.println("✅ Распакован: " + currentFile);
                    }
                }
                currentFile = null;
                continue;
            }

            if (inCodeBlock && currentFile != null) {
                content.append(line).append("\n");
            }
        }

        System.out.printf("%n🎉 Готово! Распаковано файлов: %d в директорию: %s%n", filesExtracted, targetDir);
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

            for (int i = 0; i < COMPILED_SECRETS.size(); i++) {
                if (COMPILED_SECRETS.get(i).matcher(rel).find()) {
                    foundReason = SECRET_PATTERNS.get(i)[1];
                    break;
                }
            }

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

    // ── FilteredTreeModel ─────────────────────────────────────────────────────

    static class FilteredTreeModel implements TreeModel {
        private final Path baseDir;
        private CheckboxTreeNode rootNode;
        private final List<TreeModelListener> listeners = new ArrayList<>();
        private final Map<CheckboxTreeNode, List<CheckboxTreeNode>> cache = new HashMap<>();
        private String filter = "";

        FilteredTreeModel(Path baseDir, CheckboxTreeNode rootNode) {
            this.baseDir = baseDir;
            this.rootNode = rootNode;
        }

        void setFilter(String f) {
            String nf = (f == null ? "" : f.trim()).toLowerCase(Locale.ROOT);
            if (nf.equals(filter)) return;
            filter = nf;
            cache.clear();
            fireStructureChanged();
        }

        String getFilter() { return filter; }

        void reload() { cache.clear(); fireStructureChanged(); }

        void setRoot(CheckboxTreeNode newRoot) {
            rootNode = newRoot;
            cache.clear();
            fireStructureChanged();
        }

        private boolean matchesFile(CheckboxTreeNode n) {
            String name = n.path.getFileName().toString().toLowerCase(Locale.ROOT);
            if (name.contains(filter)) return true;
            String rel = baseDir.relativize(n.path).toString().replace('\\', '/').toLowerCase(Locale.ROOT);
            return rel.contains(filter);
        }

        private boolean isVisible(CheckboxTreeNode n) {
            if (filter.isEmpty()) return true;
            if (n.isFile) return matchesFile(n);
            return !visibleChildren(n).isEmpty();
        }

        private List<CheckboxTreeNode> visibleChildren(CheckboxTreeNode parent) {
            List<CheckboxTreeNode> list = cache.get(parent);
            if (list != null) return list;
            list = new ArrayList<>();
            Enumeration<?> e = parent.children();
            while (e.hasMoreElements()) {
                CheckboxTreeNode ch = (CheckboxTreeNode) e.nextElement();
                if (isVisible(ch)) list.add(ch);
            }
            cache.put(parent, list);
            return list;
        }

        int countVisibleFiles() {
            int c = 0;
            Enumeration<?> e = rootNode.depthFirstEnumeration();
            while (e.hasMoreElements()) {
                CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
                if (n.isFile && (filter.isEmpty() || matchesFile(n))) c++;
            }
            return c;
        }

        @Override public Object getRoot() { return rootNode; }
        @Override public Object getChild(Object parent, int index) {
            return visibleChildren((CheckboxTreeNode) parent).get(index);
        }
        @Override public int getChildCount(Object parent) {
            return parent instanceof CheckboxTreeNode n ? visibleChildren(n).size() : 0;
        }
        @Override public boolean isLeaf(Object node) {
            return node instanceof CheckboxTreeNode n && n.isFile;
        }
        @Override public void valueForPathChanged(TreePath path, Object newValue) {}
        @Override public int getIndexOfChild(Object parent, Object child) {
            return parent instanceof CheckboxTreeNode n ? visibleChildren(n).indexOf(child) : -1;
        }
        @Override public void addTreeModelListener(TreeModelListener l) { listeners.add(l); }
        @Override public void removeTreeModelListener(TreeModelListener l) { listeners.remove(l); }

        private void fireStructureChanged() {
            TreeModelEvent e = new TreeModelEvent(this, new Object[]{ rootNode });
            for (TreeModelListener l : new ArrayList<>(listeners)) l.treeStructureChanged(e);
        }
    }

    // ── UI ───────────────────────────────────────────────────────────────────

    static class ScanUi {
        final Path root;
        final boolean ignoreSecretsDefault;
        CheckboxTreeNode treeRoot;
        FilteredTreeModel treeModel;
        JTree tree;
        JComboBox<String> regexBox;
        JTextField searchField;
        javax.swing.Timer searchTimer;
        JLabel statusLabel;
        JCheckBox ignoreSecretsBox;
        List<String> history;
        JDialog helpDialog;
        JButton okBtn;
        javax.swing.Timer progressTimer;

        ScanUi(Path root, boolean ignoreSecretsDefault) {
            this.root = root;
            this.ignoreSecretsDefault = ignoreSecretsDefault;
        }

        void show() {
            history = loadHistory(root);

            JFrame frame = new JFrame("Select Files to Send to Perplexity");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(620, 740);
            frame.setLocationRelativeTo(null);
            frame.setLayout(new BorderLayout(0, 4));
            buildUi(frame);
            frame.setVisible(true);
            log("UI: window open, loading index…");

            progressTimer = new javax.swing.Timer(200, e -> {
                if (statusLabel != null && statusLabel.getClientProperty("busy") == Boolean.TRUE)
                    statusLabel.setText("Indexing project… dirs: " + SCAN_DIRS.get() + ", files: " + SCAN_FILES.get());
            });
            progressTimer.start();

            SwingWorker<Void, Void> loader = new SwingWorker<>() {
                @Override protected Void doInBackground() {
                    SCAN_DIRS.set(0);
                    SCAN_FILES.set(0);
                    IndexData idx = loadIndex(root);
                    if (idx != null && indexFresh(root, idx.dirMtimes())) {
                        log("UI: index cache fresh (" + idx.dirMtimes().size() + " dirs)");
                        publishTree(idx.root(), false, true);
                        return null;
                    }
                    if (idx != null) {
                        log("UI: cache stale — showing cached tree, refreshing in background…");
                        publishTree(idx.root(), false, true);
                    } else {
                        log("UI: no cache — full scan…");
                    }
                    CheckboxTreeNode fresh = buildTree(root, root);
                    try { saveIndex(root, fresh); } catch (Exception ignored) {}
                    log("UI: scan done (" + SCAN_DIRS.get() + " dirs, " + SCAN_FILES.get() + " files), cache saved");
                    publishTree(fresh, idx != null, idx == null);
                    return null;
                }
                @Override protected void done() {
                    try { get(); } catch (Exception ex) { ex.printStackTrace(); }
                }
            };
            loader.execute();
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
            regexPanel.setBorder(new EmptyBorder(6, 8, 2, 8));
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

            // ── search panel ──
            searchField = new JTextField();
            searchField.putClientProperty("JTextField.placeholderText", "Search: type file/class name or path part… (Esc to clear)");
            searchField.putClientProperty("JTextField.showClearButton", true);

            searchTimer = new javax.swing.Timer(180, e -> applySearch());
            searchTimer.setRepeats(false);
            searchField.getDocument().addDocumentListener(new DocumentListener() {
                @Override public void insertUpdate(DocumentEvent e) { searchTimer.restart(); }
                @Override public void removeUpdate(DocumentEvent e) { searchTimer.restart(); }
                @Override public void changedUpdate(DocumentEvent e) { searchTimer.restart(); }
            });
            searchField.addKeyListener(new KeyAdapter() {
                @Override public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                        searchField.setText("");
                    }
                }
            });

            JButton selectVisibleBtn = new JButton("Select visible");
            JButton deselectVisibleBtn = new JButton("Deselect visible");
            selectVisibleBtn.setMargin(new Insets(2, 8, 2, 8));
            deselectVisibleBtn.setMargin(new Insets(2, 8, 2, 8));

            selectVisibleBtn.addActionListener(e -> selectVisible(true));
            deselectVisibleBtn.addActionListener(e -> selectVisible(false));

            JPanel searchPanel = new JPanel(new BorderLayout(6, 0));
            searchPanel.setBorder(new EmptyBorder(2, 8, 6, 8));
            searchPanel.add(new JLabel("Search:"), BorderLayout.WEST);
            searchPanel.add(searchField, BorderLayout.CENTER);

            JPanel selectBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            selectBtns.add(selectVisibleBtn);
            selectBtns.add(deselectVisibleBtn);
            searchPanel.add(selectBtns, BorderLayout.EAST);

            JPanel northPanel = new JPanel();
            northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));
            northPanel.add(regexPanel);
            northPanel.add(searchPanel);

            // ── tree (временный пустой корень, данные придут фоном) ──
            treeRoot = new CheckboxTreeNode(root, false, root.getFileName().toString());
            treeModel = new FilteredTreeModel(root, treeRoot);
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
            statusLabel = new JLabel("Indexing project…");
            statusLabel.putClientProperty("busy", Boolean.TRUE);
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

            okBtn = new JButton("OK");
            okBtn.setEnabled(false);
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

            frame.add(northPanel,  BorderLayout.NORTH);
            frame.add(scroll,      BorderLayout.CENTER);
            frame.add(bottomPanel, BorderLayout.SOUTH);
            frame.getRootPane().setDefaultButton(okBtn);

            // ── Горячие клавиши ──
            InputMap im = frame.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
            ActionMap am = frame.getRootPane().getActionMap();
            im.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK), "selectVisible");
            im.put(KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK), "deselectVisible");
            am.put("selectVisible", new AbstractAction() {
                @Override public void actionPerformed(ActionEvent e) { selectVisible(true); }
            });
            am.put("deselectVisible", new AbstractAction() {
                @Override public void actionPerformed(ActionEvent e) { selectVisible(false); }
            });
        }

        // ── select/deselect visible ───────────────────────────────────────────

        void selectVisible(boolean select) {
            String filter = treeModel.getFilter();
            int count = 0;
            Enumeration<?> e = treeRoot.depthFirstEnumeration();
            while (e.hasMoreElements()) {
                CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
                if (!n.isFile) continue;
                String name = n.path.getFileName().toString().toLowerCase(Locale.ROOT);
                String rel = root.relativize(n.path).toString().replace('\\', '/').toLowerCase(Locale.ROOT);
                boolean matches = filter.isEmpty() || name.contains(filter) || rel.contains(filter);
                if (matches) {
                    n.checked = select;
                    count++;
                }
            }
            propagateAllUp(treeRoot);
            treeModel.reload();
            tree.repaint();
            updateStatus();
            statusLabel.setText((select ? "✓ Selected " : "✗ Deselected ") + count + " visible files");
            statusLabel.setForeground(select ? new Color(0, 120, 0) : new Color(180, 0, 0));
        }

        // ── живой поиск ───────────────────────────────────────────────────────

        void applySearch() {
            String q = searchField.getText() == null ? "" : searchField.getText();
            treeModel.setFilter(q);
            if (q.trim().isEmpty()) {
                tree.collapseRow(0);
                tree.expandRow(0);
            } else {
                expandAllRows();
            }
            updateStatus();
        }

        void expandAllRows() {
            int old = -1;
            while (old != tree.getRowCount()) {
                old = tree.getRowCount();
                for (int i = 0; i < tree.getRowCount(); i++) tree.expandRow(i);
            }
        }

        // ── генерация с подтверждением по секретам ────────────────────────────

        void generate(JFrame frame, JButton okBtn) {
            List<Path> selected = collectChecked(treeRoot);
            if (selected.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Не выбрано ни одного файла.",
                        "Пусто", JOptionPane.WARNING_MESSAGE);
                return;
            }
            okBtn.setEnabled(false);
            okBtn.setText("Scanning...");
            boolean skipSecrets = !ignoreSecretsBox.isSelected();

            SwingWorker<GenerateResult, Void> scanner = new SwingWorker<>() {
                @Override protected GenerateResult doInBackground() {
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
                    return new GenerateResult(buildOutputName(root), toWrite.size(), foundSecrets, toWrite);
                }

                @Override protected void done() {
                    try {
                        GenerateResult r = get();

                        if (!r.secretFiles().isEmpty()) {
                            StringBuilder msg = new StringBuilder(
                                    "⚠️ Следующие файлы могут содержать секреты и будут ИСКЛЮЧЕНЫ из выгрузки:\n");
                            for (SecretFile sf : r.secretFiles()) {
                                msg.append("\n  • ")
                                        .append(root.relativize(sf.path()).toString().replace('\\', '/'))
                                        .append("  [").append(sf.reason()).append("]");
                            }
                            msg.append("\n\nСгенерировать файл без них?");

                            Object[] opts = { "Сгенерировать без них", "Вернуться к выбору" };
                            int choice = JOptionPane.showOptionDialog(frame, msg.toString(),
                                    "Найдены возможные секреты",
                                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE,
                                    null, opts, opts[1]);

                            if (choice != JOptionPane.YES_OPTION) {
                                okBtn.setEnabled(true);
                                okBtn.setText("OK");
                                return;
                            }
                        }

                        writeAndFinish(frame, okBtn, r);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(frame, "Ошибка: " + ex.getMessage(),
                                "Ошибка", JOptionPane.ERROR_MESSAGE);
                        okBtn.setEnabled(true);
                        okBtn.setText("OK");
                    }
                }
            };
            scanner.execute();
        }

        void writeAndFinish(JFrame frame, JButton okBtn, GenerateResult r) {
            okBtn.setText("Writing...");
            SwingWorker<Void, Void> writer = new SwingWorker<>() {
                @Override protected Void doInBackground() throws Exception {
                    writeMarkdown(root, r.toWrite(), r.outFile());
                    return null;
                }
                @Override protected void done() {
                    try {
                        get();
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(frame, "Ошибка записи: " + ex.getMessage(),
                                "Ошибка", JOptionPane.ERROR_MESSAGE);
                        okBtn.setEnabled(true);
                        okBtn.setText("OK");
                        return;
                    }
                    StringBuilder msg = new StringBuilder("Готово!\n")
                            .append(r.outFile()).append("\n(").append(r.fileCount()).append(" файлов)");
                    if (!r.secretFiles().isEmpty())
                        msg.append("\n\nИсключено файлов с секретами: ").append(r.secretFiles().size());
                    JOptionPane.showMessageDialog(frame, msg.toString(),
                            "Успех", JOptionPane.INFORMATION_MESSAGE);
                    frame.dispose();
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

        void publishTree(CheckboxTreeNode newRoot, boolean preserveChecks, boolean first) {
            try { uiWarm.await(); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            SwingUtilities.invokeLater(() -> {
                if (preserveChecks && treeRoot != null) {
                    Map<String, Boolean> checks = snapshotChecks(treeRoot);
                    applyChecks(newRoot, checks);
                }
                propagateAllUp(newRoot);
                treeRoot = newRoot;
                treeModel.setRoot(newRoot);
                if (first) {
                    if (progressTimer != null) progressTimer.stop();
                    statusLabel.putClientProperty("busy", null);
                    if (okBtn != null) okBtn.setEnabled(true);
                }
                tree.collapseRow(0);
                tree.expandRow(0);
                updateStatus();
                if (first) log("UI: tree attached, ready");
            });
        }

        Map<String, Boolean> snapshotChecks(CheckboxTreeNode node) {
            Map<String, Boolean> m = new HashMap<>();
            Enumeration<?> e = node.depthFirstEnumeration();
            while (e.hasMoreElements()) {
                CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
                if (n.isFile && n.checked)
                    m.put(root.relativize(n.path).toString().replace('\\', '/'), Boolean.TRUE);
            }
            return m;
        }

        void applyChecks(CheckboxTreeNode node, Map<String, Boolean> checks) {
            Enumeration<?> e = node.depthFirstEnumeration();
            while (e.hasMoreElements()) {
                CheckboxTreeNode n = (CheckboxTreeNode) e.nextElement();
                if (n.isFile)
                    n.checked = checks.containsKey(root.relativize(n.path).toString().replace('\\', '/'));
            }
        }

        void updateStatus() {
            if (statusLabel == null) return;
            int count = collectChecked(treeRoot).size();
            String suffix = "";
            if (treeModel != null && !treeModel.getFilter().isEmpty())
                suffix = "  |  search: " + treeModel.countVisibleFiles() + " match";
            if (count == 0) {
                statusLabel.setText("No files selected" + suffix);
                statusLabel.setForeground(Color.GRAY);
            } else {
                statusLabel.setText("✓ Selected " + count + " files" + suffix);
                statusLabel.setForeground(new Color(0, 100, 0));
            }
        }

        // ── Help dialog ───────────────────────────────────────────────────────

        void showHelp(JFrame parent) {
            if (helpDialog != null && helpDialog.isVisible()) {
                helpDialog.toFront();
                return;
            }

            helpDialog = new JDialog(parent, "Regex Examples", false);
            helpDialog.setSize(700, 500);
            helpDialog.setLocationRelativeTo(parent);

            String[][] data = {
                    { ".*\\.java$", "Все Java-файлы" },
                    { ".*\\.(java|kt|kts)$", "Java + Kotlin" },
                    { ".*\\.(xml|yml|yaml|properties)$", "Все конфиги" },
                    { "src/main/.*\\.java$", "Только production-код (без тестов)" },
                    { "src/test/.*\\.java$", "Только тесты" },
                    { ".*Service.*\\.java$", "Все сервисы (по части имени)" },
                    { ".*Controller.*\\.java$", "Все контроллеры" },
                    { ".*Repository.*\\.java$", "Репозитории/DAO" },
                    { "^.*\\.gradle(\\.kts)?$", "Все gradle-файлы" },
                    { "build\\.gradle$", "Корневой build-файл" },
                    { "Application\\.java$", "Main-класс (обычно один)" },
                    { "module-\\w+/.*\\.java$", "Любой подмодуль module-xxx" },
                    { ".*\\.properties$", ".properties (для локалей)" },
                    { "^((?!Test|IT).)*\\.java$", "Java без тестов и интеграционных" },
                    { "docker/.*", "Всё из папки docker" },
                    { "README\\.md$", "Только ридми" },
                    { ".*\\.(java|xml|yml)$", "Java + XML + YAML" },
                    { "app/src/.*\\.(kt|kts)$", "Kotlin в модуле app" },
                    { "^((?!\\.min\\.).)*\\.js$", "JS без минифицированных" }
            };
            String[] cols = { "Regex", "Описание" };

            JTable table = new JTable(data, cols) {
                @Override public boolean isCellEditable(int row, int column) { return false; }
            };
            table.getColumnModel().getColumn(0).setPreferredWidth(250);
            table.getColumnModel().getColumn(1).setPreferredWidth(400);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.setRowHeight(24);

            table.addMouseListener(new MouseAdapter() {
                @Override public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        int row = table.getSelectedRow();
                        if (row >= 0) {
                            String regex = (String) table.getValueAt(row, 0);
                            ((JTextField) regexBox.getEditor().getEditorComponent()).setText(regex);
                            regexBox.requestFocusInWindow();
                        }
                    }
                }
            });

            JScrollPane scrollPane = new JScrollPane(table);

            JTextArea syntaxArea = new JTextArea(
                    "Синтаксис: . — любой символ, .* — любое количество, $ — конец строки,\n" +
                            "(a|b) — или, (?!) — отрицание. Двойной клик по строке вставляет regex в поле."
            );
            syntaxArea.setEditable(false);
            syntaxArea.setOpaque(false);
            syntaxArea.setFont(syntaxArea.getFont().deriveFont(Font.ITALIC, 11f));
            syntaxArea.setBorder(new EmptyBorder(4, 8, 4, 8));

            JButton copyAllBtn = new JButton("Copy all examples");
            copyAllBtn.addActionListener(e -> {
                StringBuilder sb = new StringBuilder();
                for (String[] row : data) {
                    sb.append(row[0]).append("  —  ").append(row[1]).append("\n");
                }
                StringSelection selection = new StringSelection(sb.toString());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                JOptionPane.showMessageDialog(helpDialog, "Скопировано в буфер обмена!",
                        "Готово", JOptionPane.INFORMATION_MESSAGE);
            });

            JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
            bottomPanel.add(copyAllBtn);

            helpDialog.setLayout(new BorderLayout());
            helpDialog.add(syntaxArea, BorderLayout.NORTH);
            helpDialog.add(scrollPane, BorderLayout.CENTER);
            helpDialog.add(bottomPanel, BorderLayout.SOUTH);
            helpDialog.setVisible(true);
        }
    }

    record GenerateResult(String outFile, int fileCount, List<SecretFile> secretFiles, List<Path> toWrite) {}

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
        SCAN_DIRS.incrementAndGet();
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
                    if (isIncludedFile(entry)) { files.add(entry); SCAN_FILES.incrementAndGet(); }
                }
            }
        } catch (IOException ignored) {}
        dirs .sort(Comparator.naturalOrder());
        files.sort(Comparator.naturalOrder());
        // параллельная рекурсия по подкаталогам — заметно быстрее на больших проектах
        List<CheckboxTreeNode> sub = dirs.parallelStream()
                .map(d -> buildTree(root, d))
                .toList();
        for (CheckboxTreeNode sn : sub) node.add(sn);
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
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern(OUTPUT_TS_FORMAT));
        return OUTPUT_NAME_FORMAT.formatted(root.getFileName(), ts);
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
        if (GENERATED_MD.matcher(name).matches()) return false;
        return INCLUDED_EXTENSIONS.stream().anyMatch(name::endsWith);
    }
}