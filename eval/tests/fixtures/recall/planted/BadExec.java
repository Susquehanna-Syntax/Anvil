// Planted for the candidates-per-scan control: a command built from a caller's string. Never
// executed. GitLab's java_inject_rule-CommandInjection is a taint rule whose sources include a
// String parameter and whose sinks include Runtime.exec, so the source here is a String parameter.
public class BadExec {
    public static void run(String command) throws Exception {
        Runtime rt = Runtime.getRuntime();
        rt.exec(command);
    }
}
