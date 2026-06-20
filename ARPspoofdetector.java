/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package arpspoofdetector;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author USER-PC
 */
public class ARPspoofdetector {

    /**
     * @param args the command line arguments
     */
    
    
    public static void main(String[] args) 
{
    String gatewayIp = args.length > 0 ? args[0] : "192.168.1.1";
    
    Map<String, String> baseline = getArpTable();
    System.out.println("[STARTUP] Baseline captured: " + baseline.size() + " entries");
    
    for (String ip : baseline.keySet()) {
        System.out.println("  " + ip + " -> " + baseline.get(ip));
    }

    while (true) 
    {
        try 
        {
            Thread.sleep(3000);
            Map<String, String> current = getArpTable();
            compare(baseline, current, gatewayIp);
        } 
        catch (InterruptedException e) 
        {
            e.printStackTrace();
        }
    }
}
    public static Map<String, String> getArpTable()
    {
        Map<String, String> arpTable = new HashMap<>();
        
        try
        {
        ProcessBuilder PB = new ProcessBuilder("arp" , "-a"); // Blue Print for commands. WE must seperate into 2 arguments
           Process process = PB.start(); //OS launches the command as a seperate running program
           
           BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream())); //Allow java to read data. from ouput of our commmand
           
        
           String macPattern = "[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}";

           
           String line;
           
           
           while((line = reader.readLine()) !=null) //reads output line by line until theres no more output
           {
               String[] fullToken = line.trim().split("\\s+");
               if(fullToken.length == 3 && fullToken[1].matches(macPattern)&& fullToken[2].equals("dynamic"))
           {
               arpTable.put(fullToken[0], fullToken[1]);
           }
           }
           process.waitFor();
           
           
            
            return arpTable;

    }
        catch(Exception e)
        {
            e.printStackTrace();
            return new HashMap<>();
        }
        }
   public static void compare(Map<String, String> baseline, Map<String, String> current, String gatewayIp)
{
    // Check 1 - INFO: new device
    for (String ip : current.keySet()) 
    {
        if (!baseline.containsKey(ip)) 
        {
            System.out.println("[INFO] New device detected: " + ip + " -> " + current.get(ip));
        }
    }
    
    // Check 2 - INFO: device gone
    for (String ip : baseline.keySet()) 
    {
        if (!current.containsKey(ip)) 
        {
            System.out.println("[INFO] Device gone: " + ip);
        }
    }
    
    // Check 3 - WARNING / HIGH: MAC changed
    for (String ip : current.keySet()) 
    {
        if (baseline.containsKey(ip)) 
        {
            if (!baseline.get(ip).equals(current.get(ip))) 
            {
                if (ip.equals(gatewayIp)) 
                {
                    System.out.println("[HIGH] Gateway MAC changed: " + ip + " was " + baseline.get(ip) + " now " + current.get(ip));
                } 
                else 
                {
                    System.out.println("[WARNING] MAC changed: " + ip + " was " + baseline.get(ip) + " now " + current.get(ip));
                }
            }
        }
    }
}
}