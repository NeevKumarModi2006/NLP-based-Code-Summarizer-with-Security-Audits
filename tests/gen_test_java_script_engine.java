import javax.script.*;
public class Script {
    public void eval(String code) throws Exception {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("js");
        // VULNERABLE: Script Injection
        engine.eval(code);
    }
}