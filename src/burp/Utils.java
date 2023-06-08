package burp;

public class Utils {
    public enum OS {
        WINDOWS, LINUX, MAC, SOLARIS
    };
    public static OS getOperatingSystem(){
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            return OS.WINDOWS;
        }else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            return OS.LINUX;
        }else if (os.contains("mac")) {
            return OS.MAC;
        }else if (os.contains("sunos")) {
            return OS.SOLARIS;
        }
        return null;
    }
    public static int exec(String[] command){
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command(command);
        try {
            Process process = processBuilder.start();
            int exitVal = process.waitFor();
            return exitVal;
        }catch(Exception e){
            return -1;
        }
    }
    public static String toWslPath(String path){
        String wslPath = path.replace("\\", "/");
        wslPath = Character.toLowerCase(wslPath.charAt(0)) + wslPath.substring(1);
        wslPath = "/mnt/".concat(wslPath.replace(":","/"));
        return wslPath;
    }
    public static String htmlEncode(String s){
        s.replace("&", "&amp;");
        s.replace("<","&lt;");
        s.replace("<","&gt;");
        s.replace("\"","&quot;");
        s.replace("'", "&#x27");
        return s;
    }
}
