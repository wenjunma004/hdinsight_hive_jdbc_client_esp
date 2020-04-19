package com.microsoft.hdinsight;
/**
 * HiveClient.java - a demo class how to connect esp cluster.
 * @author  Wenjun Ma
 * @version 1.0
 */
import org.apache.hadoop.security.UserGroupInformation;

import java.sql.*;

public class HiveClient {

    private static String HiveDriverName = "org.apache.hive.jdbc.HiveDriver";
    private static String jdbcUrl = "dbc:hive2://zk0-llaphw.securehadooprc.onmicrosoft.com:2181,zk1-llaphw.securehadooprc.onmicrosoft.com:2181,zk3-llaphw.securehadooprc.onmicrosoft.com:2181/;serviceDiscoveryMode=zooKeeper;zooKeeperNamespace=hiveserver2-interactive;principal=hive/_HOST@SECUREHADOOPRC.ONMICROSOFT.COM";

    public static void main(String[] args) throws Exception {
        Class.forName(HiveDriverName);
        org.apache.hadoop.conf.Configuration conf = new org.apache.hadoop.conf.Configuration();
        conf.set("hadoop.security.authentication", "Kerberos");
        UserGroupInformation.setConfiguration(conf);
        UserGroupInformation.loginUserFromKeytab("hive/_HOST@SECUREHADOOPRC.ONMICROSOFT.COM", "/etc/security/keytabs/hive.service.keytab");
        Connection con = DriverManager.getConnection(jdbcUrl);
        System.out.println("\nGot Connection: " + con);
        System.out.println("\nRun show tables command and listing 'default' Database tables of hive.");
        Statement stmt = con.createStatement();
        String sql = "show tables";
        System.out.println("\nExecuting Query: " + sql);
        ResultSet rs = stmt.executeQuery(sql);
        System.out.println("\n-----------------Result start------------------");
        while (rs.next()) {
            System.out.println(rs.getString(1));
        }
        System.out.println("\n-----------------Result end--------------------");
    }
}
