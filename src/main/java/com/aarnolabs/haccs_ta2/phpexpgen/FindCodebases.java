package com.aarnolabs.haccs_ta2.phpexpgen;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindCodebases {

    public static void main(String args[]) throws IOException {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(args[0])));) {
            String line;
            while ((line = in.readLine()) != null) {
                String cols[] = line.split(",");
                if (!cols[0].trim().equals(""))
                    continue;
                
                Pattern p = Pattern.compile("SQL injection vulnerability in ([^\\s]+) in (.*) allows");
                Matcher m = p.matcher(cols[3].trim());
                if (m.find()) {
                    String vulnFile = m.group(1);
                    String codebase = m.group(2);
                    String cveInfo = cols[1].trim();
                    System.out.printf("[%s:%s] %s\n", cveInfo, vulnFile, codebase);
                }
            }
        }
    }
    
}
