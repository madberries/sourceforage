package com.aarnolabs.haccs_ta2.phpexpgen;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;
import java.util.concurrent.Callable;

public abstract class BaseCmd implements Callable<Integer> {
    
    protected String cve, version, cpeProduct;
    protected File vulnFile;
    
    @Override
    public Integer call() throws Exception {
        File propFile = new File(".cve.properties");
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(propFile)) {
            props.load(in);
        }

        cve = getProperty(props, "cve");
        version = getProperty(props, "version");
        cpeProduct = getProperty(props, "cpe.product");
        vulnFile = new File(getProperty(props, "vuln.file"));
        
        return 0;
    }

    protected String getProperty(Properties props, String key) {
        String val = props.getProperty(key);
        if (val == null) {
            throw new RuntimeException(String.format("Missing property for key \"%s\"", key));
        }
        return val;
    }

}
