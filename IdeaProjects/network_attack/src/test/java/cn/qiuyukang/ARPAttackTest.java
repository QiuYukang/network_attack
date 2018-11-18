package cn.qiuyukang;

import jpcap.NetworkInterface;
import org.junit.Test;

import java.net.InetAddress;

import static cn.qiuyukang.ARPAttack.getAllNIC;

public class ARPAttackTest {
    /**
     * 测试获取所有网络接口
     * 如果某个网络接口显示的ip地址是ipv6而不是ipv4地址说明不支持该网络接口！
     */
    @Test
    public void getAllNICTest() {
        ARPAttack.getAllNIC();
    }

    @Test
    public void arpScan() {
        NetworkInterface[] devices = getAllNIC();
        // 将接口改成自己想要的网络接口索引即可
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