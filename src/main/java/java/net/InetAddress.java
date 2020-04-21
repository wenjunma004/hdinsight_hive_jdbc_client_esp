//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package java.net;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.ObjectStreamField;
import java.io.Serializable;
import java.io.ObjectInputStream.GetField;
import java.io.ObjectOutputStream.PutField;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.atomic.AtomicLong;
import jdk.internal.misc.JavaNetInetAddressAccess;
import jdk.internal.misc.SharedSecrets;
import jdk.internal.misc.Unsafe;
import sun.net.InetAddressCachePolicy;
import sun.net.util.IPAddressUtil;
import sun.security.action.GetPropertyAction;

public class InetAddress implements Serializable {
    static final int PREFER_IPV4_VALUE = 0;
    static final int PREFER_IPV6_VALUE = 1;
    static final int PREFER_SYSTEM_VALUE = 2;
    static final int IPv4 = 1;
    static final int IPv6 = 2;
    static final transient int preferIPv6Address;
    final transient InetAddress.InetAddressHolder holder = new InetAddress.InetAddressHolder();
    private static transient InetAddress.NameService nameService = null;
    private transient String canonicalHostName = null;
    private static final long serialVersionUID = 3286316764910316507L;
    private static final ConcurrentMap<String, InetAddress.Addresses> cache;
    private static final NavigableSet<InetAddress.CachedAddresses> expirySet;
    static final InetAddressImpl impl;
    private static volatile InetAddress.CachedLocalHost cachedLocalHost;
    private static final Unsafe UNSAFE;
    private static final long FIELDS_OFFSET;
    private static final ObjectStreamField[] serialPersistentFields;

    InetAddress.InetAddressHolder holder() {
        return this.holder;
    }

    InetAddress() {
    }

    private Object readResolve() throws ObjectStreamException {
        return new Inet4Address(this.holder().getHostName(), this.holder().getAddress());
    }

    public boolean isMulticastAddress() {
        return false;
    }

    public boolean isAnyLocalAddress() {
        return false;
    }

    public boolean isLoopbackAddress() {
        return false;
    }

    public boolean isLinkLocalAddress() {
        return false;
    }

    public boolean isSiteLocalAddress() {
        return false;
    }

    public boolean isMCGlobal() {
        return false;
    }

    public boolean isMCNodeLocal() {
        return false;
    }

    public boolean isMCLinkLocal() {
        return false;
    }

    public boolean isMCSiteLocal() {
        return false;
    }

    public boolean isMCOrgLocal() {
        return false;
    }

    public boolean isReachable(int timeout) throws IOException {
        return this.isReachable((NetworkInterface)null, 0, timeout);
    }

    public boolean isReachable(NetworkInterface netif, int ttl, int timeout) throws IOException {
        if (ttl < 0) {
            throw new IllegalArgumentException("ttl can't be negative");
        } else if (timeout < 0) {
            throw new IllegalArgumentException("timeout can't be negative");
        } else {
            return impl.isReachable(this, timeout, netif, ttl);
        }
    }

    public String getHostName() {
        return this.getHostName(true);
    }

    String getHostName(boolean check) {
        if (this.holder().getHostName() == null) {
            this.holder().hostName = getHostFromNameService(this, check);
        }

        return this.holder().getHostName();
    }

    public String getCanonicalHostName() {
        String value = this.canonicalHostName;
        System.out.println("------------------>InetAddress:" + value);
        if (value == null) {
            this.canonicalHostName = value = getHostFromNameService(this, true);
        }

        return value;
    }

    private static String getHostFromNameService(InetAddress addr, boolean check) {
        String host = null;

        try {
            host = nameService.getHostByAddr(addr.getAddress());
            if (check) {
                SecurityManager sec = System.getSecurityManager();
                if (sec != null) {
                    sec.checkConnect(host, -1);
                }
            }

            InetAddress[] arr = getAllByName0(host, check);
            boolean ok = false;
            if (arr != null) {
                for(int i = 0; !ok && i < arr.length; ++i) {
                    ok = addr.equals(arr[i]);
                }
            }

            if (!ok) {
                host = addr.getHostAddress();
                return host;
            }
        } catch (SecurityException var6) {
            host = addr.getHostAddress();
        } catch (UnknownHostException var7) {
            host = addr.getHostAddress();
        }

        return host;
    }

    public byte[] getAddress() {
        return null;
    }

    public String getHostAddress() {
        return null;
    }

    public int hashCode() {
        return -1;
    }

    public boolean equals(Object obj) {
        return false;
    }

    public String toString() {
        String hostName = this.holder().getHostName();
        return Objects.toString(hostName, "") + "/" + this.getHostAddress();
    }

    private static InetAddress.NameService createNameService() {
        String hostsFileName = GetPropertyAction.privilegedGetProperty("jdk.net.hosts.file");
        Object theNameService;
        if (hostsFileName != null) {
            theNameService = new InetAddress.HostsFileNameService(hostsFileName);
        } else {
            theNameService = new InetAddress.PlatformNameService();
        }

        return (InetAddress.NameService)theNameService;
    }

    public static InetAddress getByAddress(String host, byte[] addr) throws UnknownHostException {
        if (host != null && !host.isEmpty() && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
            host = host.substring(1, host.length() - 1);
        }

        if (addr != null) {
            if (addr.length == 4) {
                return new Inet4Address(host, addr);
            }

            if (addr.length == 16) {
                byte[] newAddr = IPAddressUtil.convertFromIPv4MappedAddress(addr);
                if (newAddr != null) {
                    return new Inet4Address(host, newAddr);
                }

                return new Inet6Address(host, addr);
            }
        }

        throw new UnknownHostException("addr is of illegal length");
    }

    public static InetAddress getByName(String host) throws UnknownHostException {
        return getAllByName(host)[0];
    }

    private static InetAddress getByName(String host, InetAddress reqAddr) throws UnknownHostException {
        return getAllByName(host, reqAddr)[0];
    }

    public static InetAddress[] getAllByName(String host) throws UnknownHostException {
        return getAllByName(host, (InetAddress)null);
    }

    private static InetAddress[] getAllByName(String host, InetAddress reqAddr) throws UnknownHostException {
        if (host != null && !host.isEmpty()) {
            boolean ipv6Expected = false;
            if (host.charAt(0) == '[') {
                if (host.length() <= 2 || host.charAt(host.length() - 1) != ']') {
                    throw new UnknownHostException(host + ": invalid IPv6 address");
                }

                host = host.substring(1, host.length() - 1);
                ipv6Expected = true;
            }

            if (Character.digit(host.charAt(0), 16) == -1 && host.charAt(0) != ':') {
                if (ipv6Expected) {
                    throw new UnknownHostException("[" + host + "]");
                }
            } else {
                byte[] addr = null;
                int numericZone = -1;
                String ifname = null;
                byte[] addr = IPAddressUtil.textToNumericFormatV4(host);
                if (addr == null) {
                    int pos;
                    if ((pos = host.indexOf(37)) != -1) {
                        numericZone = checkNumericZone(host);
                        if (numericZone == -1) {
                            ifname = host.substring(pos + 1);
                        }
                    }

                    if ((addr = IPAddressUtil.textToNumericFormatV6(host)) == null && host.contains(":")) {
                        throw new UnknownHostException(host + ": invalid IPv6 address");
                    }
                } else if (ipv6Expected) {
                    throw new UnknownHostException("[" + host + "]");
                }

                InetAddress[] ret = new InetAddress[1];
                if (addr != null) {
                    if (addr.length == 4) {
                        ret[0] = new Inet4Address((String)null, addr);
                    } else if (ifname != null) {
                        ret[0] = new Inet6Address((String)null, addr, ifname);
                    } else {
                        ret[0] = new Inet6Address((String)null, addr, numericZone);
                    }

                    return ret;
                }
            }

            return getAllByName0(host, reqAddr, true, true);
        } else {
            InetAddress[] ret = new InetAddress[]{impl.loopbackAddress()};
            return ret;
        }
    }

    public static InetAddress getLoopbackAddress() {
        return impl.loopbackAddress();
    }

    private static int checkNumericZone(String s) throws UnknownHostException {
        int percent = s.indexOf(37);
        int slen = s.length();
        int zone = 0;
        if (percent == -1) {
            return -1;
        } else {
            for(int i = percent + 1; i < slen; ++i) {
                char c = s.charAt(i);
                if (c == ']') {
                    if (i == percent + 1) {
                        return -1;
                    }
                    break;
                }

                int digit;
                if ((digit = Character.digit(c, 10)) < 0) {
                    return -1;
                }

                zone = zone * 10 + digit;
            }

            return zone;
        }
    }

    private static InetAddress[] getAllByName0(String host) throws UnknownHostException {
        return getAllByName0(host, true);
    }

    static InetAddress[] getAllByName0(String host, boolean check) throws UnknownHostException {
        return getAllByName0(host, (InetAddress)null, check, true);
    }

    private static InetAddress[] getAllByName0(String host, InetAddress reqAddr, boolean check, boolean useCache) throws UnknownHostException {
        if (check) {
            SecurityManager security = System.getSecurityManager();
            if (security != null) {
                security.checkConnect(host, -1);
            }
        }

        long now = System.nanoTime();
        Iterator var6 = expirySet.iterator();

        while(var6.hasNext()) {
            InetAddress.CachedAddresses caddrs = (InetAddress.CachedAddresses)var6.next();
            if (caddrs.expiryTime - now >= 0L) {
                break;
            }

            if (expirySet.remove(caddrs)) {
                cache.remove(caddrs.host, caddrs);
            }
        }

        Object addrs;
        if (useCache) {
            addrs = (InetAddress.Addresses)cache.get(host);
        } else {
            addrs = (InetAddress.Addresses)cache.remove(host);
            if (addrs != null) {
                if (addrs instanceof InetAddress.CachedAddresses) {
                    expirySet.remove(addrs);
                }

                addrs = null;
            }
        }

        if (addrs == null) {
            InetAddress.Addresses oldAddrs = (InetAddress.Addresses)cache.putIfAbsent(host, addrs = new InetAddress.NameServiceAddresses(host, reqAddr));
            if (oldAddrs != null) {
                addrs = oldAddrs;
            }
        }

        return (InetAddress[])((InetAddress.Addresses)addrs).get().clone();
    }

    static InetAddress[] getAddressesFromNameService(String host, InetAddress reqAddr) throws UnknownHostException {
        InetAddress[] addresses = null;
        UnknownHostException ex = null;

        try {
            addresses = nameService.lookupAllHostAddr(host);
        } catch (UnknownHostException var8) {
            if (host.equalsIgnoreCase("localhost")) {
                addresses = new InetAddress[]{impl.loopbackAddress()};
            } else {
                ex = var8;
            }
        }

        if (addresses == null) {
            throw ex == null ? new UnknownHostException(host) : ex;
        } else {
            if (reqAddr != null && addresses.length > 1 && !addresses[0].equals(reqAddr)) {
                int i;
                for(i = 1; i < addresses.length && !addresses[i].equals(reqAddr); ++i) {
                }

                if (i < addresses.length) {
                    InetAddress tmp2 = reqAddr;

                    for(int j = 0; j < i; ++j) {
                        InetAddress tmp = addresses[j];
                        addresses[j] = tmp2;
                        tmp2 = tmp;
                    }

                    addresses[i] = tmp2;
                }
            }

            return addresses;
        }
    }

    public static InetAddress getByAddress(byte[] addr) throws UnknownHostException {
        return getByAddress((String)null, addr);
    }

    public static InetAddress getLocalHost() throws UnknownHostException {
        SecurityManager security = System.getSecurityManager();

        try {
            InetAddress.CachedLocalHost clh = cachedLocalHost;
            if (clh != null && clh.expiryTime - System.nanoTime() >= 0L) {
                if (security != null) {
                    security.checkConnect(clh.host, -1);
                }

                return clh.addr;
            } else {
                String local = impl.getLocalHostName();
                if (security != null) {
                    security.checkConnect(local, -1);
                }

                InetAddress localAddr;
                if (local.equals("localhost")) {
                    localAddr = impl.loopbackAddress();
                } else {
                    try {
                        localAddr = getAllByName0(local, (InetAddress)null, false, false)[0];
                    } catch (UnknownHostException var6) {
                        UnknownHostException uhe2 = new UnknownHostException(local + ": " + var6.getMessage());
                        uhe2.initCause(var6);
                        throw uhe2;
                    }
                }

                cachedLocalHost = new InetAddress.CachedLocalHost(local, localAddr);
                return localAddr;
            }
        } catch (SecurityException var7) {
            return impl.loopbackAddress();
        }
    }

    private static native void init();

    static InetAddress anyLocalAddress() {
        return impl.anyLocalAddress();
    }

    static InetAddressImpl loadImpl(String implName) {
        Object impl = null;
        String prefix = GetPropertyAction.privilegedGetProperty("impl.prefix", "");

        Object tmp;
        try {
            tmp = Class.forName("java.net." + prefix + implName).newInstance();
            impl = tmp;
        } catch (ClassNotFoundException var5) {
            System.err.println("Class not found: java.net." + prefix + implName + ":\ncheck impl.prefix property in your properties file.");
        } catch (InstantiationException var6) {
            System.err.println("Could not instantiate: java.net." + prefix + implName + ":\ncheck impl.prefix property in your properties file.");
        } catch (IllegalAccessException var7) {
            System.err.println("Cannot access class: java.net." + prefix + implName + ":\ncheck impl.prefix property in your properties file.");
        }

        if (impl == null) {
            try {
                tmp = Class.forName(implName).newInstance();
                impl = tmp;
            } catch (Exception var4) {
                throw new Error("System property impl.prefix incorrect");
            }
        }

        return (InetAddressImpl)impl;
    }

    private void readObjectNoData() throws IOException, ClassNotFoundException {
        if (this.getClass().getClassLoader() != null) {
            throw new SecurityException("invalid address type");
        }
    }

    private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
        if (this.getClass().getClassLoader() != null) {
            throw new SecurityException("invalid address type");
        } else {
            GetField gf = s.readFields();
            String host = (String)gf.get("hostName", (Object)null);
            int address = gf.get("address", 0);
            int family = gf.get("family", 0);
            if (family != 1 && family != 2) {
                throw new InvalidObjectException("invalid address family type: " + family);
            } else {
                InetAddress.InetAddressHolder h = new InetAddress.InetAddressHolder(host, address, family);
                UNSAFE.putObject(this, FIELDS_OFFSET, h);
            }
        }
    }

    private void writeObject(ObjectOutputStream s) throws IOException {
        if (this.getClass().getClassLoader() != null) {
            throw new SecurityException("invalid address type");
        } else {
            PutField pf = s.putFields();
            pf.put("hostName", this.holder().getHostName());
            pf.put("address", this.holder().getAddress());
            pf.put("family", this.holder().getFamily());
            s.writeFields();
        }
    }

    static {
        String str = (String)AccessController.doPrivileged(new GetPropertyAction("java.net.preferIPv6Addresses"));
        if (str == null) {
            preferIPv6Address = 0;
        } else if (str.equalsIgnoreCase("true")) {
            preferIPv6Address = 1;
        } else if (str.equalsIgnoreCase("false")) {
            preferIPv6Address = 0;
        } else if (str.equalsIgnoreCase("system")) {
            preferIPv6Address = 2;
        } else {
            preferIPv6Address = 0;
        }

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Void run() {
                System.loadLibrary("net");
                return null;
            }
        });
        SharedSecrets.setJavaNetInetAddressAccess(new JavaNetInetAddressAccess() {
            public String getOriginalHostName(InetAddress ia) {
                return ia.holder.getOriginalHostName();
            }

            public InetAddress getByName(String hostName, InetAddress hostAddress) throws UnknownHostException {
                return InetAddress.getByName(hostName, hostAddress);
            }
        });
        init();
        cache = new ConcurrentHashMap();
        expirySet = new ConcurrentSkipListSet();
        impl = InetAddressImplFactory.create();
        nameService = createNameService();
        UNSAFE = Unsafe.getUnsafe();
        FIELDS_OFFSET = UNSAFE.objectFieldOffset(InetAddress.class, "holder");
        serialPersistentFields = new ObjectStreamField[]{new ObjectStreamField("hostName", String.class), new ObjectStreamField("address", Integer.TYPE), new ObjectStreamField("family", Integer.TYPE)};
    }

    private static final class CachedLocalHost {
        final String host;
        final InetAddress addr;
        final long expiryTime = System.nanoTime() + 5000000000L;

        CachedLocalHost(String host, InetAddress addr) {
            this.host = host;
            this.addr = addr;
        }
    }

    private static final class HostsFileNameService implements InetAddress.NameService {
        private final String hostsFile;

        public HostsFileNameService(String hostsFileName) {
            this.hostsFile = hostsFileName;
        }

        private String addrToString(byte[] addr) {
            String stringifiedAddress = null;
            if (addr.length == 4) {
                stringifiedAddress = Inet4Address.numericToTextFormat(addr);
            } else {
                byte[] newAddr = IPAddressUtil.convertFromIPv4MappedAddress(addr);
                if (newAddr != null) {
                    stringifiedAddress = Inet4Address.numericToTextFormat(addr);
                } else {
                    stringifiedAddress = Inet6Address.numericToTextFormat(addr);
                }
            }

            return stringifiedAddress;
        }

        public String getHostByAddr(byte[] addr) throws UnknownHostException {
            String host = null;
            String addrString = this.addrToString(addr);

            try {
                Scanner hostsFileScanner = new Scanner(new File(this.hostsFile), "UTF-8");

                try {
                    while(hostsFileScanner.hasNextLine()) {
                        String hostEntry = hostsFileScanner.nextLine();
                        if (!hostEntry.startsWith("#")) {
                            hostEntry = this.removeComments(hostEntry);
                            if (hostEntry.contains(addrString)) {
                                host = this.extractHost(hostEntry, addrString);
                                if (host != null) {
                                    break;
                                }
                            }
                        }
                    }
                } catch (Throwable var9) {
                    try {
                        hostsFileScanner.close();
                    } catch (Throwable var8) {
                        var9.addSuppressed(var8);
                    }

                    throw var9;
                }

                hostsFileScanner.close();
            } catch (FileNotFoundException var10) {
                throw new UnknownHostException("Unable to resolve address " + addrString + " as hosts file " + this.hostsFile + " not found ");
            }

            if (host != null && !host.equals("") && !host.equals(" ")) {
                return host;
            } else {
                throw new UnknownHostException("Requested address " + addrString + " resolves to an invalid entry in hosts file " + this.hostsFile);
            }
        }

        public InetAddress[] lookupAllHostAddr(String host) throws UnknownHostException {
            String addrStr = null;
            InetAddress[] res = null;
            byte[] addr = new byte[4];
            ArrayList inetAddresses = null;

            try {
                Scanner hostsFileScanner = new Scanner(new File(this.hostsFile), "UTF-8");

                try {
                    while(hostsFileScanner.hasNextLine()) {
                        String hostEntry = hostsFileScanner.nextLine();
                        if (!hostEntry.startsWith("#")) {
                            hostEntry = this.removeComments(hostEntry);
                            if (hostEntry.contains(host)) {
                                addrStr = this.extractHostAddr(hostEntry, host);
                                if (addrStr != null && !addrStr.equals("")) {
                                    addr = this.createAddressByteArray(addrStr);
                                    if (inetAddresses == null) {
                                        inetAddresses = new ArrayList(1);
                                    }

                                    if (addr != null) {
                                        inetAddresses.add(InetAddress.getByAddress(host, addr));
                                    }
                                }
                            }
                        }
                    }
                } catch (Throwable var11) {
                    try {
                        hostsFileScanner.close();
                    } catch (Throwable var10) {
                        var11.addSuppressed(var10);
                    }

                    throw var11;
                }

                hostsFileScanner.close();
            } catch (FileNotFoundException var12) {
                throw new UnknownHostException("Unable to resolve host " + host + " as hosts file " + this.hostsFile + " not found ");
            }

            if (inetAddresses != null) {
                res = (InetAddress[])inetAddresses.toArray(new InetAddress[inetAddresses.size()]);
                return res;
            } else {
                throw new UnknownHostException("Unable to resolve host " + host + " in hosts file " + this.hostsFile);
            }
        }

        private String removeComments(String hostsEntry) {
            String filteredEntry = hostsEntry;
            int hashIndex;
            if ((hashIndex = hostsEntry.indexOf("#")) != -1) {
                filteredEntry = hostsEntry.substring(0, hashIndex);
            }

            return filteredEntry;
        }

        private byte[] createAddressByteArray(String addrStr) {
            byte[] addrArray = IPAddressUtil.textToNumericFormatV4(addrStr);
            if (addrArray == null) {
                addrArray = IPAddressUtil.textToNumericFormatV6(addrStr);
            }

            return addrArray;
        }

        private String extractHostAddr(String hostEntry, String host) {
            String[] mapping = hostEntry.split("\\s+");
            String hostAddr = null;
            if (mapping.length >= 2) {
                for(int i = 1; i < mapping.length; ++i) {
                    if (mapping[i].equalsIgnoreCase(host)) {
                        hostAddr = mapping[0];
                    }
                }
            }

            return hostAddr;
        }

        private String extractHost(String hostEntry, String addrString) {
            String[] mapping = hostEntry.split("\\s+");
            String host = null;
            if (mapping.length >= 2 && mapping[0].equalsIgnoreCase(addrString)) {
                host = mapping[1];
            }

            return host;
        }
    }

    private static final class PlatformNameService implements InetAddress.NameService {
        private PlatformNameService() {
        }

        public InetAddress[] lookupAllHostAddr(String host) throws UnknownHostException {
            return InetAddress.impl.lookupAllHostAddr(host);
        }

        public String getHostByAddr(byte[] addr) throws UnknownHostException {
            return InetAddress.impl.getHostByAddr(addr);
        }
    }

    private interface NameService {
        InetAddress[] lookupAllHostAddr(String var1) throws UnknownHostException;

        String getHostByAddr(byte[] var1) throws UnknownHostException;
    }

    private static final class NameServiceAddresses implements InetAddress.Addresses {
        private final String host;
        private final InetAddress reqAddr;

        NameServiceAddresses(String host, InetAddress reqAddr) {
            this.host = host;
            this.reqAddr = reqAddr;
        }

        public InetAddress[] get() throws UnknownHostException {
            Object addresses;
            synchronized(this) {
                addresses = (InetAddress.Addresses)InetAddress.cache.putIfAbsent(this.host, this);
                if (addresses == null) {
                    addresses = this;
                }

                if (addresses == this) {
                    InetAddress[] inetAddresses;
                    UnknownHostException ex;
                    int cachePolicy;
                    try {
                        inetAddresses = InetAddress.getAddressesFromNameService(this.host, this.reqAddr);
                        ex = null;
                        cachePolicy = InetAddressCachePolicy.get();
                    } catch (UnknownHostException var8) {
                        inetAddresses = null;
                        ex = var8;
                        cachePolicy = InetAddressCachePolicy.getNegative();
                    }

                    if (cachePolicy == 0) {
                        InetAddress.cache.remove(this.host, this);
                    } else {
                        InetAddress.CachedAddresses cachedAddresses = new InetAddress.CachedAddresses(this.host, inetAddresses, cachePolicy == -1 ? 0L : System.nanoTime() + 1000000000L * (long)cachePolicy);
                        if (InetAddress.cache.replace(this.host, this, cachedAddresses) && cachePolicy != -1) {
                            InetAddress.expirySet.add(cachedAddresses);
                        }
                    }

                    if (inetAddresses == null) {
                        throw ex == null ? new UnknownHostException(this.host) : ex;
                    }

                    return inetAddresses;
                }
            }

            return ((InetAddress.Addresses)addresses).get();
        }
    }

    private static final class CachedAddresses implements InetAddress.Addresses, Comparable<InetAddress.CachedAddresses> {
        private static final AtomicLong seq = new AtomicLong();
        final String host;
        final InetAddress[] inetAddresses;
        final long expiryTime;
        final long id;

        CachedAddresses(String host, InetAddress[] inetAddresses, long expiryTime) {
            this.id = seq.incrementAndGet();
            this.host = host;
            this.inetAddresses = inetAddresses;
            this.expiryTime = expiryTime;
        }

        public InetAddress[] get() throws UnknownHostException {
            if (this.inetAddresses == null) {
                throw new UnknownHostException(this.host);
            } else {
                return this.inetAddresses;
            }
        }

        public int compareTo(InetAddress.CachedAddresses other) {
            long diff = this.expiryTime - other.expiryTime;
            if (diff < 0L) {
                return -1;
            } else {
                return diff > 0L ? 1 : Long.compare(this.id, other.id);
            }
        }
    }

    private interface Addresses {
        InetAddress[] get() throws UnknownHostException;
    }

    static class InetAddressHolder {
        String originalHostName;
        String hostName;
        int address;
        int family;

        InetAddressHolder() {
        }

        InetAddressHolder(String hostName, int address, int family) {
            this.originalHostName = hostName;
            this.hostName = hostName;
            this.address = address;
            this.family = family;
        }

        void init(String hostName, int family) {
            this.originalHostName = hostName;
            this.hostName = hostName;
            if (family != -1) {
                this.family = family;
            }

        }

        String getHostName() {
            return this.hostName;
        }

        String getOriginalHostName() {
            return this.originalHostName;
        }

        int getAddress() {
            return this.address;
        }

        int getFamily() {
            return this.family;
        }
    }
}
