import os
import struct
import socket
import ipaddress

class QQWry:
    def __init__(self, db_path):
        self.db_path = db_path
        self.fp = None
        self.first_ip = None
        self.last_ip = None
        self.total_ip = None

    def open(self):
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"Database file {self.db_path} not found.")
        self.fp = open(self.db_path, 'rb')
        self.first_ip = self._get_long()
        self.last_ip = self._get_long()
        self.total_ip = (self.last_ip - self.first_ip) // 7

    def close(self):
        if self.fp:
            self.fp.close()

    def _get_long(self):
        return struct.unpack('<L', self.fp.read(4))[0]

    def _get_long3(self):
        return struct.unpack('<L', self.fp.read(3) + b'\x00')[0]

    def _get_string(self):
        result = b''
        while True:
            char = self.fp.read(1)
            if char == b'\x00':
                break
            result += char
        return result.decode('gbk')

    def _get_area(self):
        byte = self.fp.read(1)
        if byte == b'\x00':
            return ""
        elif byte in (b'\x01', b'\x02'):
            self.fp.seek(self._get_long3())
            return self._get_string()
        else:
            return self._get_string(byte)

    def get_location(self, ip):
        if not self.fp:
            self.open()

        ip_num = self._ip2long(ip)
        l, u = 0, self.total_ip
        find_ip = self.last_ip

        while l <= u:
            i = (l + u) // 2
            self.fp.seek(self.first_ip + i * 7)
            begin_ip = self._get_long()
            self.fp.seek(self._get_long3())
            end_ip = self._get_long()

            if ip_num < begin_ip:
                u = i - 1
            elif ip_num > end_ip:
                l = i + 1
            else:
                find_ip = self.first_ip + i * 7
                break

        self.fp.seek(find_ip)
        begin_ip = self._get_long()
        offset = self._get_long3()
        self.fp.seek(offset)
        end_ip = self._get_long()
        byte = self.fp.read(1)

        if byte == b'\x01':
            country_offset = self._get_long3()
            self.fp.seek(country_offset)
            byte = self.fp.read(1)
            if byte == b'\x02':
                self.fp.seek(self._get_long3())
                country = self._get_string()
                self.fp.seek(country_offset + 4)
                area = self._get_area()
            else:
                country = self._get_string(byte)
                area = self._get_area()
        elif byte == b'\x02':
            self.fp.seek(self._get_long3())
            country = self._get_string()
            self.fp.seek(offset + 8)
            area = self._get_area()
        else:
            country = self._get_string(byte)
            area = self._get_area()

        country = country.replace(" CZ88.NET", "").replace("纯真网络", "无数据")
        area = area.replace(" CZ88.NET", "")

        return {
            'ip': ip,
            'country': country,
            'area': area
        }

    def _ip2long(self, ip):
        return struct.unpack('!L', socket.inet_aton(ip))[0]


class IPv6Wry:
    def __init__(self, db_path):
        self.db_path = db_path
        self.fp = None
        self.index_start_offset = None
        self.index_end_offset = None
        self.offlen = None
        self.iplen = None
        self.total = None

    def open(self):
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"Database file {self.db_path} not found.")
        self.fp = open(self.db_path, 'rb')
        self._initialize()

    def close(self):
        if self.fp:
            self.fp.close()

    def _initialize(self):
        self.fp.seek(16)
        self.index_start_offset = self._read8()
        self.offlen = self._read1(6)
        self.iplen = self._read1(7)
        self.total = self._read8(8)
        self.index_end_offset = self.index_start_offset + (self.iplen + self.offlen) * self.total

    def _read1(self, offset=None):
        if offset is not None:
            self.fp.seek(offset)
        return struct.unpack('B', self.fp.read(1))[0]

    def _read8(self, offset=None, size=8):
        if offset is not None:
            self.fp.seek(offset)
        return struct.unpack('<Q', self.fp.read(size) + b'\x00' * (8 - size))[0]

    def _readstr(self, offset=None):
        if offset is not None:
            self.fp.seek(offset)
        result = b''
        while True:
            char = self.fp.read(1)
            if char == b'\x00':
                break
            result += char
        # return result.decode('gbk')
        return result.decode('utf-8', errors="ignore")


    def _read_record(self, offset):
        flag = self._read1(offset)
        if flag == 1:
            location_offset = self._read8(offset + 1, self.offlen)
            return self._read_record(location_offset)
        country = self._read_location(offset)
        if flag == 2:
            area = self._read_location(offset + self.offlen + 1)
        else:
            area = self._read_location(offset + len(country) + 1)
        return [country, area]

    def _read_location(self, offset):
        if offset == 0:
            return ""
        flag = self._read1(offset)
        if flag == 0:
            return ""
        if flag == 2:
            offset = self._read8(offset + 1, self.offlen)
            return self._read_location(offset)
        return self._readstr(offset)

    def get_location(self, ip):
        if not self.fp:
            self.open()

        ip_bin = socket.inet_pton(socket.AF_INET6, ip)
        ip_num1, ip_num2 = struct.unpack('>QQ', ip_bin)
        ip_find = self._find(ip_num1, ip_num2, 0, self.total)
        ip_offset = self.index_start_offset + ip_find * (self.iplen + self.offlen)
        ip_offset2 = ip_offset + self.iplen + self.offlen
        ip_start = socket.inet_ntop(socket.AF_INET6, struct.pack('>QQ', self._read8(ip_offset), 0))
        try:
            ip_end = socket.inet_ntop(socket.AF_INET6, struct.pack('>QQ', self._read8(ip_offset2) - 1, 0))
        except Exception:
            ip_end = "FFFF:FFFF:FFFF:FFFF::"
        ip_record_offset = self._read8(ip_offset + self.iplen, self.offlen)
        ip_addr = self._read_record(ip_record_offset)
        return {
            'ip': ip,
            'country': ip_addr[0],
            'area': ip_addr[1]
        }

    def _find(self, ip_num1, ip_num2, l, r):
        if l + 1 >= r:
            return l
        m = (l + r) // 2
        m_ip1 = self._read8(self.index_start_offset + m * (self.iplen + self.offlen), self.iplen)
        m_ip2 = 0
        if self.iplen <= 8:
            m_ip1 <<= 8 * (8 - self.iplen)
        else:
            m_ip2 = self._read8(self.index_start_offset + m * (self.iplen + self.offlen) + 8, self.iplen - 8)
            m_ip2 <<= 8 * (16 - self.iplen)
        if self._uint64cmp(ip_num1, m_ip1) < 0:
            return self._find(ip_num1, ip_num2, l, m)
        if self._uint64cmp(ip_num1, m_ip1) > 0:
            return self._find(ip_num1, ip_num2, m, r)
        if self._uint64cmp(ip_num2, m_ip2) < 0:
            return self._find(ip_num1, ip_num2, l, m)
        return self._find(ip_num1, ip_num2, m, r)

    def _uint64cmp(self, a, b):
        if (a >= 0 and b >= 0) or (a < 0 and b < 0):
            return (a > b) - (a < b)
        if a >= 0 and b < 0:
            return -1
        return 1


class IpLocation:
    def __init__(self, qqwry_path, ipv6wry_path):
        self.qqwry = QQWry(qqwry_path)
        self.ipv6wry = IPv6Wry(ipv6wry_path)

    def get_location(self, ip):
        try:
            if ipaddress.ip_address(ip).version == 4:
                return self.qqwry.get_location(ip)
            else:
                return self.ipv6wry.get_location(ip)
        except Exception as e:
            return {'error': str(e)}

    def close(self):
        self.qqwry.close()
        self.ipv6wry.close()


# 使用示例
if __name__ == "__main__":
    qqwry_path = './db/qqwry.dat'
    ipv6wry_path = './db/ipv6wry.db'

    ip_location = IpLocation(qqwry_path, ipv6wry_path)

    # 查询IPv4
    ipv4_result = ip_location.get_location('163.177.65.160')
    print(ipv4_result)

    # 查询IPv6
    ipv6_result = ip_location.get_location('2409:8a28:e9e:2d44:60c3:24e7:4640:abc0')
    print(ipv6_result)

    ip_location.close()