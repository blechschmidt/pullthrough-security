// Evaluates versions and version ranges with maven-artifact's
// ComparableVersion and VersionRange. Inputs: files of JSON-quoted strings.
// Usage: java -cp maven-artifact.jar:. MvnRef versions.lines constraints.lines outdir
import java.nio.file.*;
import java.util.*;
import org.apache.maven.artifact.versioning.*;

public class MvnRef {
    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20 || c == 0x7f) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    static String unq(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 1; i < s.length() - 1; i++) {
            char c = s.charAt(i);
            if (c != '\\') { b.append(c); continue; }
            char e = s.charAt(++i);
            switch (e) {
                case 'n': b.append('\n'); break;
                case 't': b.append('\t'); break;
                case 'r': b.append('\r'); break;
                case 'u': b.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16)); i += 4; break;
                default: b.append(e);
            }
        }
        return b.toString();
    }
    public static void main(String[] a) throws Exception {
        List<String> vers = new ArrayList<>(new LinkedHashSet<>(Files.readAllLines(Paths.get(a[0])))).stream().filter(l -> !l.isEmpty()).map(MvnRef::unq).collect(java.util.stream.Collectors.toList());
        List<String> cons = new ArrayList<>(new LinkedHashSet<>(Files.readAllLines(Paths.get(a[1])))).stream().filter(l -> !l.isEmpty()).map(MvnRef::unq).collect(java.util.stream.Collectors.toList());
        // ComparableVersion is not transitive on every input, so no sort:
        // each version's direct comparison with every matrix version.
        List<String> matrix = new ArrayList<>();
        for (String v : vers) if (v.matches("[A-Za-z0-9._+-]+")) matrix.add(v);
        StringBuilder out = new StringBuilder("# [");
        for (int i = 0; i < matrix.size(); i++) out.append(i > 0 ? "," : "").append(q(matrix.get(i)));
        out.append("]\n");
        for (String v : vers) {
            ComparableVersion c = new ComparableVersion(v);
            StringBuilder row = new StringBuilder();
            for (String m : matrix) { int r = c.compareTo(new ComparableVersion(m)); row.append(r < 0 ? '<' : r == 0 ? '=' : '>'); }
            out.append(q(v)).append('\t').append(row).append('\n');
        }
        Files.write(Paths.get(a[2], "maven-versions.tsv"), out.toString().getBytes("UTF-8"));
        List<String> universe = new ArrayList<>();
        for (String v : vers) if (v.matches("[0-9][A-Za-z0-9._+-]*") && universe.size() < 220) universe.add(v);
        out = new StringBuilder("# [");
        for (int i = 0; i < universe.size(); i++) out.append(i > 0 ? "," : "").append(q(universe.get(i)));
        out.append("]\n");
        for (String c : cons) {
            VersionRange vr;
            try { vr = VersionRange.createFromVersionSpec(c); } catch (Exception e) { out.append(q(c)).append("\tinvalid\t\t\n"); continue; }
            if (vr == null || vr.getRecommendedVersion() != null || vr.getRestrictions().isEmpty()) { out.append(q(c)).append("\tsoft\t\t\n"); continue; }
            StringBuilder bits = new StringBuilder();
            for (String u : universe) bits.append(vr.containsVersion(new DefaultArtifactVersion(u)) ? '1' : '0');
            out.append(q(c)).append("\tok\t\t").append(bits).append('\n');
        }
        Files.write(Paths.get(a[2], "maven-constraints.tsv"), out.toString().getBytes("UTF-8"));
        System.out.println(vers.size() + " versions, " + universe.size() + " universe, " + cons.size() + " ranges");
    }
}
