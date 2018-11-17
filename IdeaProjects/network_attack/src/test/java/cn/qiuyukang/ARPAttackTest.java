package cn.qiuyukang;

import jpcap.NetworkInterface;
import org.junit.Test;

import java.net.InetAddress;

import static cn.qiuyukang.ARPAttack.getAllNIC;
import static org.junit.Assert.*;

public class ARPAttackTest {
    @Test
    public void getAllNICTest() {
        ARPAttack.getAllNIC();
    }

    @Test
    public void arpScan() {
        NetworkInterface[] devices = getAllNIC();
        NetworkInterface device = devices[4];

        try {
            ARPAttack.arpScan(device);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void attackHost() {
        NetworkInterface[] devices = getAllNIC();
        NetworkInterface device = devices[4];
        try {
            ARPAttack.attackHost(device, "192.168.31.136", "CE-22-33-44-55-66");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void attackHosts() {
    }

}