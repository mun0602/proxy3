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

echo -e "${BLUE}=== CÀI ĐẶT V2RAY HTTP BRIDGE + CHỐNG RÒ RỈ DNS ===${NC}"

# Lấy địa chỉ IP công cộng
PUBLIC_IP=$(curl -s https://checkip.amazonaws.com || curl -s https://api.ipify.org || curl -s https://ifconfig.me)
if [ -z "$PUBLIC_IP" ]; then
  echo -e "${YELLOW}Không thể xác định địa chỉ IP công cộng. Sử dụng IP local thay thế.${NC}"
  PUBLIC_IP=$(hostname -I | awk '{print $1}')
fi

# Thông số cấu hình
HTTP_PROXY_PORT=8118
SS_PORT=8388
WS_PORT=10086
SS_PASSWORD=$(cat /proc/sys/kernel/random/uuid | tr -d '-' | head -c 16)
SS_METHOD="chacha20-ietf-poly1305"
UUID=$(cat /proc/sys/kernel/random/uuid)
WS_PATH="/$(head /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1)"

#############################################
# PHẦN 1: CẤU HÌNH HỆ THỐNG VÀ RAM ẢO
#############################################

echo -e "${GREEN}[1/7] Cấu hình hệ thống và RAM ảo...${NC}"

# Tạo 2GB swap nếu chưa có
if [ "$(free | grep -c Swap)" -eq 0 ] || [ "$(free | grep Swap | awk '{print $2}')" -lt 1000000 ]; then
    echo -e "${YELLOW}Tạo 2GB RAM ảo (swap)...${NC}"
    swapoff -a &>/dev/null
    rm -f /swapfile
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
    fi
fi

# Cấu hình swap
echo -e "${YELLOW}Tối ưu cấu hình swap...${NC}"
cat > /etc/sysctl.d/99-swap.conf << EOF
# Giảm swappiness để ưu tiên sử dụng RAM
vm.swappiness = 10
# Tăng giá trị cache để cải thiện hiệu suất
vm.vfs_cache_pressure = 50
# Tối ưu hóa kết nối mạng
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fastopen = 3
EOF
sysctl -p /etc/sysctl.d/99-swap.conf

# Tắt IPv6
cat > /etc/sysctl.d/99-disable-ipv6.conf << EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p /etc/sysctl.d/99-disable-ipv6.conf

# Tối ưu hóa limits.conf cho hiệu suất
cat > /etc/security/limits.d/proxy-limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

#############################################
# PHẦN 2: CÀI ĐẶT PHẦN MỀM
#############################################

echo -e "${GREEN}[2/7] Cài đặt các gói cần thiết...${NC}"
apt update -y
apt install -y curl wget unzip jq dnsutils net-tools nginx iptables-persistent resolvconf

# Cài đặt DNSMasq
apt install -y dnsmasq

#############################################
# PHẦN 3: CÀI ĐẶT V2RAY
#############################################

echo -e "${GREEN}[3/7] Cài đặt và cấu hình V2Ray...${NC}"

# Kiểm tra nếu V2Ray đã được cài đặt
if [ ! -f "/usr/local/bin/v2ray" ]; then
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
else
    echo -e "${YELLOW}V2Ray đã được cài đặt. Đang cập nhật...${NC}"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
fi

# Tạo thư mục log nếu không tồn tại
mkdir -p /var/log/v2ray
touch /var/log/v2ray/access.log
touch /var/log/v2ray/error.log
chown -R nobody:nogroup /var/log/v2ray 2>/dev/null || true

# Tạo cấu hình V2Ray tối ưu với DNS bảo mật
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
            "id": "$UUID",
            "alterId": 0,
            "security": "auto"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$WS_PATH"
        },
        "sockopt": {
          "tcpFastOpen": true,
          "tproxy": "redirect"
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
        "method": "$SS_METHOD",
        "password": "$SS_PASSWORD",
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

# Tối ưu V2Ray service
cat > /etc/systemd/system/v2ray.service << EOF
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

#############################################
# PHẦN 4: CẤU HÌNH DNSMASQ CHỐNG RÒ RỈ DNS
#############################################

echo -e "${GREEN}[4/7] Cấu hình DNSMasq để chống rò rỉ DNS...${NC}"

# Cấu hình dnsmasq
cat > /etc/dnsmasq.conf << EOF
# Lắng nghe trên localhost
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

# Cấu hình bảo mật
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

#############################################
# PHẦN 5: THIẾT LẬP IPTABLES
#############################################

echo -e "${GREEN}[5/7] Thiết lập Iptables để bảo vệ hệ thống...${NC}"

# Lưu lại các rule hiện tại (nếu có)
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4.backup
fi

# Xóa tất cả các rule hiện tại
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Thiết lập policy mặc định
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Cho phép lưu lượng trên loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Cho phép các kết nối đã thiết lập và liên quan
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Cho phép SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Cho phép HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Cho phép các cổng Proxy
iptables -A INPUT -p tcp --dport $HTTP_PROXY_PORT -j ACCEPT
iptables -A INPUT -p tcp --dport $WS_PORT -j ACCEPT
iptables -A INPUT -p tcp --dport $SS_PORT -j ACCEPT
iptables -A INPUT -p udp --dport $SS_PORT -j ACCEPT

# Từ chối tất cả các gói tin IPv6 (nếu có)
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -P INPUT DROP 2>/dev/null || true
    ip6tables -P FORWARD DROP 2>/dev/null || true
    ip6tables -P OUTPUT DROP 2>/dev/null || true
fi

# Lưu các quy tắc iptables
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
    if [ -x "$(command -v ip6tables-save)" ]; then
        ip6tables-save > /etc/iptables/rules.v6
    fi
fi

#############################################
# PHẦN 6: CẤU HÌNH PAC FILE
#############################################

echo -e "${GREEN}[6/7] Tạo PAC file chống rò rỉ DNS...${NC}"

# Tạo thư mục nếu chưa tồn tại
mkdir -p /var/www/html/proxy

# Tạo PAC file nâng cao với bảo vệ DNS leak
cat > /var/www/html/proxy/proxy.pac << EOF
function FindProxyForURL(url, host) {
    // Thêm cache buster để phá vỡ cache
    var cacheBuster = Math.floor(Math.random() * 1000000);
    
    // Mạng nội bộ kết nối trực tiếp
    if (isPlainHostName(host) || 
        shExpMatch(host, "*.local") ||
        shExpMatch(host, "*.localhost") ||
        shExpMatch(host, "localhost") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.0.0.0")) {
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

# Cấu hình Nginx để phục vụ PAC file
cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $PUBLIC_IP;
    
    access_log /var/log/nginx/v2ray-access.log;
    error_log /var/log/nginx/v2ray-error.log;
    
    root /var/www/html;
    index index.html;
    
    # Định tuyến WebSocket đến V2Ray
    location $WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$WS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60s;
        proxy_read_timeout 86400s;
        proxy_send_timeout 60s;
        
        # Tối ưu proxy buffer
        proxy_buffer_size 16k;
        proxy_buffers 8 16k;
        proxy_busy_buffers_size 32k;
    }
    
    # PAC file cho iPhone
    location /proxy/ {
        types { } 
        default_type application/x-ns-proxy-autoconfig;
        add_header Cache-Control "no-cache";
    }
}
EOF

systemctl restart nginx
systemctl enable nginx

#############################################
# PHẦN 7: TẠO SCRIPT QUẢN LÝ VÀ THÔNG TIN KẾT NỐI
#############################################

echo -e "${GREEN}[7/7] Tạo script quản lý và kiểm tra...${NC}"

# Lưu thông tin cấu hình
mkdir -p /etc/v2ray-setup
cat > /etc/v2ray-setup/config.json << EOF
{
  "http_proxy_port": $HTTP_PROXY_PORT,
  "ss_port": $SS_PORT,
  "ws_port": $WS_PORT,
  "ss_password": "$SS_PASSWORD",
  "ss_method": "$SS_METHOD",
  "uuid": "$UUID",
  "ws_path": "$WS_PATH",
  "public_ip": "$PUBLIC_IP",
  "installation_date": "$(date)",
  "version": "1.0.0"
}
EOF
chmod 600 /etc/v2ray-setup/config.json

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
netstat -tunapl | grep v2ray | grep -c ESTABLISHED

echo -e "\n${YELLOW}10 kết nối gần đây:${NC}"
tail -10 /var/log/v2ray/access.log
EOF

chmod +x /usr/local/bin/check-dnsleak.sh

# Script hiển thị thông tin kết nối
cat > /usr/local/bin/proxy-info.sh << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Lấy thông tin từ config
CONFIG_FILE="/etc/v2ray-setup/config.json"
if [ -f "$CONFIG_FILE" ]; then
  PUBLIC_IP=$(jq -r '.public_ip' "$CONFIG_FILE")
  HTTP_PROXY_PORT=$(jq -r '.http_proxy_port' "$CONFIG_FILE")
  SS_PORT=$(jq -r '.ss_port' "$CONFIG_FILE")
  WS_PORT=$(jq -r '.ws_port' "$CONFIG_FILE")
  SS_PASSWORD=$(jq -r '.ss_password' "$CONFIG_FILE")
  SS_METHOD=$(jq -r '.ss_method' "$CONFIG_FILE")
  UUID=$(jq -r '.uuid' "$CONFIG_FILE")
  WS_PATH=$(jq -r '.ws_path' "$CONFIG_FILE")
else
  PUBLIC_IP=$(curl -s https://checkip.amazonaws.com || curl -s https://api.ipify.org || curl -s https://ifconfig.me)
  HTTP_PROXY_PORT=$(grep -o '"port": [0-9]*' /usr/local/etc/v2ray/config.json | head -1 | awk '{print $2}')
  SS_PORT=$(grep -o '"port": [0-9]*' /usr/local/etc/v2ray/config.json | grep -A 5 shadowsocks | head -1 | awk '{print $2}')
  WS_PORT=$(grep -o '"port": [0-9]*' /usr/local/etc/v2ray/config.json | grep -A 5 vmess | head -1 | awk '{print $2}')
  SS_PASSWORD=$(grep -o '"password": "[^"]*"' /usr/local/etc/v2ray/config.json | head -1 | awk -F'"' '{print $4}')
  SS_METHOD=$(grep -o '"method": "[^"]*"' /usr/local/etc/v2ray/config.json | head -1 | awk -F'"' '{print $4}')
  UUID=$(grep -o '"id": "[^"]*"' /usr/local/etc/v2ray/config.json | head -1 | awk -F'"' '{print $4}')
  WS_PATH=$(grep -o '"path": "[^"]*"' /usr/local/etc/v2ray/config.json | head -1 | awk -F'"' '{print $4}')
fi

# Thống kê cơ bản về hệ thống
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
MEM_USAGE=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')
DISK_USAGE=$(df -h / | awk 'NR==2{print $5}')
UPTIME=$(uptime -p)
CONNECTIONS=$(netstat -ant | grep ESTABLISHED | grep -c ":$HTTP_PROXY_PORT")

# Tạo VMess URL
create_vmess_url() {
  local CONFIG="{\"v\":\"2\",\"ps\":\"V2Ray-WebSocket\",\"add\":\"$PUBLIC_IP\",\"port\":\"80\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$PUBLIC_IP\",\"path\":\"$WS_PATH\",\"tls\":\"\"}"
  echo "vmess://$(echo -n "$CONFIG" | base64 -w 0)"
}

# Tạo Shadowsocks URL
create_ss_url() {
  local METHOD_PASSWORD=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
  echo "ss://$METHOD_PASSWORD@$PUBLIC_IP:$SS_PORT"
}

VMESS_URL=$(create_vmess_url)
SS_URL=$(create_ss_url)

echo -e "${BLUE}===== THÔNG TIN KẾT NỐI PROXY =====${NC}"
echo -e "${YELLOW}Địa chỉ IP:${NC} ${GREEN}$PUBLIC_IP${NC}"
echo -e "${YELLOW}HTTP Proxy:${NC} ${GREEN}$PUBLIC_IP:$HTTP_PROXY_PORT${NC}"
echo -e "${YELLOW}PAC URL:${NC} ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"
echo -e "${YELLOW}Shadowsocks:${NC} ${GREEN}$PUBLIC_IP:$SS_PORT${NC}"
echo -e "${YELLOW}Shadowsocks Password:${NC} ${GREEN}$SS_PASSWORD${NC}"
echo -e "${YELLOW}Shadowsocks Method:${NC} ${GREEN}$SS_METHOD${NC}"
echo -e "${YELLOW}VMess WebSocket:${NC} ${GREEN}ws://$PUBLIC_IP:80$WS_PATH${NC}"
echo -e "${YELLOW}VMess UUID:${NC} ${GREEN}$UUID${NC}"

echo -e "\n${BLUE}===== TRẠNG THÁI HỆ THỐNG =====${NC}"
echo -e "${YELLOW}Uptime:${NC} $UPTIME"
echo -e "${YELLOW}CPU:${NC} $CPU_USAGE%"
echo -e "${YELLOW}RAM:${NC} $MEM_USAGE"
echo -e "${YELLOW}Disk:${NC} $DISK_USAGE"
echo -e "${YELLOW}Số kết nối hiện tại:${NC} $CONNECTIONS"

echo -e "\n${BLUE}===== URL CHIA SẺ =====${NC}"
echo -e "${YELLOW}VMess URL:${NC}"
echo -e "${GREEN}$VMESS_URL${NC}"
echo -e "${YELLOW}Shadowsocks URL:${NC}"
echo -e "${GREEN}$SS_URL${NC}"

echo -e "\n${BLUE}===== HƯỚNG DẪN SỬ DỤNG =====${NC}"
echo -e "${YELLOW}Cấu hình proxy PAC trên iPhone:${NC}"
echo -e "1. Settings > Wi-Fi > [Mạng Wi-Fi] > Configure Proxy"
echo -e "2. Chọn 'Automatic', nhập URL: ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"
echo -e "3. Ngoài ra, cấu hình DNS thủ công: 1.1.1.1 và 8.8.8.8"

echo -e "\n${BLUE}===== LỆNH HỮU ÍCH =====${NC}"
echo -e "Kiểm tra DNS leak: ${GREEN}sudo /usr/local/bin/check-dnsleak.sh${NC}"
echo -e "Xem thông tin kết nối: ${GREEN}sudo /usr/local/bin/proxy-info.sh${NC}"
echo -e "Khởi động lại dịch vụ: ${GREEN}sudo systemctl restart v2ray dnsmasq nginx${NC}"
echo -e "Xem log V2Ray: ${GREEN}sudo tail -f /var/log/v2ray/access.log${NC}"
EOF

chmod +x /usr/local/bin/proxy-info.sh

# Script khởi động lại dịch vụ
cat > /usr/local/bin/restart-proxy.sh << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
NC='\033[0m'

systemctl restart v2ray
systemctl restart dnsmasq
systemctl restart nginx

# Kiểm tra trạng thái
v2ray_status=$(systemctl is-active v2ray)
dnsmasq_status=$(systemctl is-active dnsmasq)
nginx_status=$(systemctl is-active nginx)

echo -e "${GREEN}V2Ray:${NC} $v2ray_status"
echo -e "${GREEN}DNSMasq:${NC} $dnsmasq_status"
echo -e "${GREEN}Nginx:${NC} $nginx_status"

echo "Tất cả dịch vụ đã được khởi động lại"
EOF

chmod +x /usr/local/bin/restart-proxy.sh

# Khởi động lại các dịch vụ
systemctl daemon-reload
systemctl enable v2ray
systemctl enable dnsmasq
systemctl enable nginx
systemctl restart v2ray
systemctl restart dnsmasq
systemctl restart nginx

# Tạo crontab để khởi động lại dịch vụ mỗi ngày
(crontab -l 2>/dev/null || echo "") | {
    cat
    echo "0 4 * * * /usr/local/bin/restart-proxy.sh > /dev/null 2>&1"
} | crontab -

# Hiển thị thông tin kết nối
echo -e "\n${BLUE}========================================================${NC}"
echo -e "${GREEN}CÀI ĐẶT HOÀN TẤT! PROXY ĐÃ SẴN SÀNG SỬ DỤNG${NC}"
echo -e "${GREEN}CHỐNG DNS LEAK ĐÃ ĐƯỢC CẤU HÌNH THÀNH CÔNG${NC}"
echo -e "${BLUE}========================================================${NC}"

echo -e "\n${YELLOW}THÔNG TIN KẾT NỐI:${NC}"
echo -e "HTTP Proxy: ${GREEN}$PUBLIC_IP:$HTTP_PROXY_PORT${NC}"
echo -e "PAC URL: ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"
echo -e "Shadowsocks: ${GREEN}$PUBLIC_IP:$SS_PORT${NC}"
echo -e "Shadowsocks Password: ${GREEN}$SS_PASSWORD${NC}"
echo -e "Shadowsocks Method: ${GREEN}$SS_METHOD${NC}"
echo -e "VMess WebSocket: ${GREEN}ws://$PUBLIC_IP:80$WS_PATH${NC}"
echo -e "VMess UUID: ${GREEN}$UUID${NC}"

echo -e "\n${YELLOW}HƯỚNG DẪN SỬ DỤNG TRÊN IPHONE:${NC}"
echo -e "1. Vào Settings > Wi-Fi > [Mạng Wi-Fi] > Configure Proxy > Auto"
echo -e "2. URL: ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"
echo -e "3. Cấu hình DNS thủ công 1.1.1.1 và 8.8.8.8 để ngăn DNS leak"

echo -e "\n${YELLOW}QUẢN LÝ HỆ THỐNG:${NC}"
echo -e "Xem thông tin kết nối: ${GREEN}sudo /usr/local/bin/proxy-info.sh${NC}"
echo -e "Kiểm tra DNS leak: ${GREEN}sudo /usr/local/bin/check-dnsleak.sh${NC}"
echo -e "Khởi động lại dịch vụ: ${GREEN}sudo /usr/local/bin/restart-proxy.sh${NC}"
echo -e "${BLUE}========================================================${NC}"
