#!/bin/bash

# Màu sắc cho output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Vui lòng chạy script với quyền root (sudo)${NC}"
  exit 1
fi

echo -e "${BLUE}=== FIX DNS LEAK VỚI HTTP PROXY (PHIÊN BẢN TỐI GIẢN) ===${NC}"

# Lấy địa chỉ IP công cộng
PUBLIC_IP=$(curl -s https://checkip.amazonaws.com || curl -s https://api.ipify.org || curl -s https://ifconfig.me)
if [ -z "$PUBLIC_IP" ]; then
  echo -e "${YELLOW}Không thể xác định địa chỉ IP công cộng. Sử dụng IP local thay thế.${NC}"
  PUBLIC_IP=$(hostname -I | awk '{print $1}')
fi

# Kiểm tra V2Ray đã cài đặt chưa
if [ ! -f "/usr/local/bin/v2ray" ]; then
  echo -e "${RED}V2Ray chưa được cài đặt. Vui lòng cài đặt V2Ray trước.${NC}"
  exit 1
fi

# Kiểm tra cấu hình V2Ray
if [ ! -f "/usr/local/etc/v2ray/config.json" ]; then
  echo -e "${RED}Không tìm thấy file cấu hình V2Ray.${NC}"
  exit 1
fi

# Đọc thông số cấu hình từ file (nếu có)
if [ -f "/etc/v2ray-setup/config.json" ]; then
  echo -e "${GREEN}Đang đọc cấu hình hiện tại...${NC}"
  HTTP_PROXY_PORT=$(jq -r '.http_proxy_port' /etc/v2ray-setup/config.json 2>/dev/null || echo "8118")
  SS_PORT=$(jq -r '.ss_port' /etc/v2ray-setup/config.json 2>/dev/null || echo "8388")
  WS_PORT=$(jq -r '.ws_port' /etc/v2ray-setup/config.json 2>/dev/null || echo "10086")
else
  # Sử dụng giá trị mặc định
  HTTP_PROXY_PORT=8118
  SS_PORT=8388
  WS_PORT=10086
fi

#############################################
# PHẦN 1: CẤU HÌNH V2RAY VỚI DNS BẢO MẬT
#############################################

echo -e "${GREEN}[1/3] Cấu hình V2Ray với DNS bảo mật...${NC}"

# Backup cấu hình cũ
cp /usr/local/etc/v2ray/config.json /usr/local/etc/v2ray/config.json.bak.$(date +%s)

# Tạo cấu hình V2Ray với DNS bảo mật
cat > /usr/local/etc/v2ray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "dns": {
    "servers": [
      "https+local://cloudflare-dns.com/dns-query",
      "1.1.1.1",
      "8.8.8.8",
      "localhost"
    ],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "port": $HTTP_PROXY_PORT,
      "listen": "0.0.0.0",
      "protocol": "http",
      "settings": {
        "timeout": 300,
        "allowTransparent": false
      },
      "tag": "http_in",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "fakedns"],
        "metadataOnly": false
      }
    },
    {
      "port": $WS_PORT,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$(cat /etc/v2ray-setup/config.json | jq -r '.uuid' 2>/dev/null || cat /proc/sys/kernel/random/uuid)",
            "alterId": 0,
            "security": "auto"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$(cat /etc/v2ray-setup/config.json | jq -r '.ws_path' 2>/dev/null || echo "/$(head /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1)")"
        }
      },
      "tag": "vmess_in",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "fakedns"],
        "metadataOnly": false
      }
    },
    {
      "port": $SS_PORT,
      "listen": "127.0.0.1",
      "protocol": "shadowsocks",
      "settings": {
        "method": "$(cat /etc/v2ray-setup/config.json | jq -r '.ss_method' 2>/dev/null || echo "chacha20-ietf-poly1305")",
        "password": "$(cat /etc/v2ray-setup/config.json | jq -r '.ss_password' 2>/dev/null || echo "$(cat /proc/sys/kernel/random/uuid | tr -d '-' | head -c 16)")",
        "network": "tcp,udp"
      },
      "tag": "ss_in",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "fakedns"],
        "metadataOnly": false
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIP",
        "dns": {
          "servers": [
            "https+local://cloudflare-dns.com/dns-query"
          ]
        }
      },
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    },
    {
      "protocol": "dns",
      "tag": "dns-out"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "dns-out",
        "network": "udp",
        "port": 53
      },
      {
        "type": "field",
        "inboundTag": ["http_in"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundTag": ["vmess_in", "ss_in"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "direct"
      }
    ]
  },
  "policy": {
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  }
}
EOF

#############################################
# PHẦN 2: CẬP NHẬT PAC FILE CHỐNG DNS LEAK
#############################################

echo -e "${GREEN}[2/3] Cập nhật PAC file để ngăn DNS leak...${NC}"

# Tạo thư mục nếu chưa tồn tại
mkdir -p /var/www/html/proxy

# Tạo PAC file nâng cao với bảo vệ DNS leak
cat > /var/www/html/proxy/proxy.pac << EOF
function FindProxyForURL(url, host) {
    // Thêm cache buster để phá vỡ cache proxy
    var cacheBuster = Math.floor(Math.random() * 1000000);
    
    // Bảo vệ DNS leak - Chuyển hướng tất cả DNS requests
    if (isPlainHostName(host) || 
        shExpMatch(host, "*.local") ||
        shExpMatch(host, "*.localhost") ||
        shExpMatch(host, "localhost")) {
        return "DIRECT";
    }

    // Chặn các trang với WebRTC có thể làm lộ IP
    if (shExpMatch(host, "*.stun.*") ||
        shExpMatch(host, "stun.*") ||
        shExpMatch(host, "*.turn.*") ||
        shExpMatch(host, "turn.*") ||
        shExpMatch(host, "*global.turn.*") ||
        shExpMatch(host, "*.webrtc.*") ||
        shExpMatch(host, "*rtcpeerconnection*")) {
        return "PROXY 127.0.0.1:1"; // Chặn với proxy không hợp lệ
    }
    
    // Chuyển hướng tất cả requests qua proxy với cache buster
    return "PROXY $PUBLIC_IP:$HTTP_PROXY_PORT?nocache=" + cacheBuster;
}
EOF

#############################################
# PHẦN 3: CẤU HÌNH DNSMASQ ĐỂ CHẶN DNS LEAK
#############################################

echo -e "${GREEN}[3/3] Cài đặt và cấu hình DNSMasq...${NC}"

# Cài đặt dnsmasq
apt-get update
apt-get install -y dnsmasq resolvconf

# Cấu hình dnsmasq
cat > /etc/dnsmasq.conf << EOF
# Lắng nghe trên tất cả các interface
listen-address=127.0.0.1
interface=lo

# Không sử dụng /etc/hosts
no-hosts

# Upstream DNS servers (DoH)
server=1.1.1.1
server=8.8.8.8

# Truy vấn song song
all-servers

# Cache DNS
cache-size=1000
min-cache-ttl=300

# Log
log-queries
log-facility=/var/log/dnsmasq.log

# Các cấu hình an toàn
bogus-priv
domain-needed
EOF

# Cấu hình resolvconf để sử dụng dnsmasq
echo "nameserver 127.0.0.1" > /etc/resolvconf/resolv.conf.d/head

# Cấu hình systemd-resolved nếu được sử dụng
if systemctl is-active --quiet systemd-resolved; then
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    
    # Đảm bảo /etc/resolv.conf trỏ đến dnsmasq
    rm -f /etc/resolv.conf
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
fi

# Khởi động dnsmasq
systemctl restart dnsmasq
systemctl enable dnsmasq

# Khởi động lại dịch vụ
systemctl restart v2ray
systemctl restart nginx

# Đặt quyền sở hữu thích hợp
chmod 644 /var/www/html/proxy/proxy.pac

echo -e "\n${BLUE}========================================================${NC}"
echo -e "${GREEN}HOÀN TẤT KHẮC PHỤC DNS LEAK!${NC}"
echo -e "${BLUE}========================================================${NC}"

echo -e "\n${YELLOW}THÔNG TIN TRUY CẬP:${NC}"
echo -e "HTTP Proxy: ${GREEN}$PUBLIC_IP:$HTTP_PROXY_PORT${NC}"
echo -e "PAC URL: ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"
if [ -f "/etc/v2ray-setup/config.json" ]; then
  V2RAY_WS_PATH=$(jq -r '.ws_path' /etc/v2ray-setup/config.json 2>/dev/null || echo "/path")
  SS_PASSWORD=$(jq -r '.ss_password' /etc/v2ray-setup/config.json 2>/dev/null || echo "password")
  SS_METHOD=$(jq -r '.ss_method' /etc/v2ray-setup/config.json 2>/dev/null || echo "chacha20-ietf-poly1305")
  UUID=$(jq -r '.uuid' /etc/v2ray-setup/config.json 2>/dev/null || echo "uuid")
  
  echo -e "VMess WebSocket: ${GREEN}ws://$PUBLIC_IP$V2RAY_WS_PATH${NC}"
  echo -e "VMess UUID: ${GREEN}$UUID${NC}"
  echo -e "Shadowsocks: ${GREEN}$PUBLIC_IP:$SS_PORT${NC}"
  echo -e "Shadowsocks Password: ${GREEN}$SS_PASSWORD${NC}"
  echo -e "Shadowsocks Method: ${GREEN}$SS_METHOD${NC}"
fi

echo -e "\n${YELLOW}HƯỚNG DẪN SỬ DỤNG TRÊN IPHONE:${NC}"
echo -e "1. Vào Settings > Wi-Fi > [Mạng Wi-Fi] > Configure Proxy > Auto"
echo -e "2. URL: ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"
echo -e "3. Hoặc cấu hình thủ công: Proxy: ${GREEN}$PUBLIC_IP${NC} Port: ${GREEN}$HTTP_PROXY_PORT${NC}"

echo -e "\n${YELLOW}Để kiểm tra DNS leak sau khi cấu hình:${NC}"
echo -e "1. Truy cập https://dnsleaktest.com (Sử dụng tiện ích đã cấu hình)"
echo -e "2. Kết quả nên hiển thị DNS thuộc vị trí proxy của bạn, không phải vị trí thật"
echo -e "${BLUE}========================================================${NC}"

# Tool kiểm tra trạng thái
cat > /usr/local/bin/check-dnsleak.sh << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}===== KIỂM TRA TRẠNG THÁI DNS LEAK PROTECT =====${NC}"
echo -e "${YELLOW}DNS Server hiện tại:${NC}"
cat /etc/resolv.conf

echo -e "\n${YELLOW}V2Ray DNS config:${NC}"
grep -A 10 '"dns"' /usr/local/etc/v2ray/config.json

echo -e "\n${YELLOW}DNSMasq status:${NC}"
systemctl status dnsmasq | grep Active

echo -e "\n${YELLOW}Kiểm tra truy vấn DNS:${NC}"
dig +short google.com

echo -e "\n${YELLOW}Kiểm tra kết nối V2Ray:${NC}"
systemctl status v2ray | grep Active

echo -e "\n${YELLOW}Thống kê kết nối HTTP proxy:${NC}"
netstat -tunapl | grep v2ray | grep ESTABLISHED | wc -l

echo -e "\n${YELLOW}10 kết nối gần đây:${NC}"
head -10 /var/log/v2ray/access.log | grep -v cloudflare-dns
EOF

chmod +x /usr/local/bin/check-dnsleak.sh

echo -e "Sử dụng lệnh ${GREEN}sudo /usr/local/bin/check-dnsleak.sh${NC} để kiểm tra trạng thái bảo vệ DNS"
