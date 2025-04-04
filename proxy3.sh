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

echo -e "${BLUE}=== SCRIPT TỐI ƯU V2RAY HTTP - SHADOWSOCKS BRIDGE VỚI 2GB RAM ẢO ===${NC}"

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

# Tạo 2GB swap
echo -e "${YELLOW}Tạo 2GB RAM ảo (swap)...${NC}"
# Xóa swap cũ nếu có
swapoff -a &>/dev/null
rm -f /swapfile

# Tạo swap mới
fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

# Thêm vào fstab nếu chưa có
if ! grep -q '/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
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

# Tối ưu hóa limits.conf cho hiệu suất
cat > /etc/security/limits.d/proxy-limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

echo -e "${GREEN}✅ RAM ảo và cấu hình hệ thống đã được tối ưu hóa${NC}"

#############################################
# PHẦN 2: CÀI ĐẶT PHẦN MỀM
#############################################

echo -e "${GREEN}[2/7] Cài đặt các gói cần thiết...${NC}"
apt update -y
apt install -y curl wget unzip jq nginx htop net-tools uuid-runtime lsb-release

# Cài đặt apt-fast nếu có thể để tăng tốc độ tải
if ! command -v apt-fast > /dev/null; then
  if command -v add-apt-repository > /dev/null; then
    add-apt-repository -y ppa:apt-fast/stable
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y apt-fast
  else
    apt install -y software-properties-common
    add-apt-repository -y ppa:apt-fast/stable
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y apt-fast
  fi
fi

# Nếu apt-fast đã được cài đặt, sử dụng nó để cài đặt các gói còn lại
if command -v apt-fast > /dev/null; then
  apt-fast install -y ca-certificates preload zlib1g-dev
else
  apt install -y ca-certificates preload zlib1g-dev
fi

# Tối ưu preload
echo -e "${YELLOW}Tối ưu hóa preload...${NC}"
cat > /etc/preload.conf << EOF
[memload]
# Tăng cache thêm 20%
memloadcycle = 120
ioprio = 3

[processes]
expiretime = 14
autosave = 60

[statfs]
timeout = 3600

[system]
maxsize = 303
EOF
systemctl enable preload
systemctl restart preload

#############################################
# PHẦN 3: CÀI ĐẶT V2RAY
#############################################

echo -e "${GREEN}[3/7] Cài đặt V2Ray...${NC}"
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Tạo thư mục log nếu không tồn tại
mkdir -p /var/log/v2ray
touch /var/log/v2ray/access.log
touch /var/log/v2ray/error.log
chown -R nobody:nogroup /var/log/v2ray

# Tối ưu cấu hình V2Ray - Sử dụng V2Ray cho HTTP và Shadowsocks
cat > /usr/local/etc/v2ray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
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
        "destOverride": ["http", "tls"]
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
        "destOverride": ["http", "tls"]
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
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIP"
      },
      "tag": "direct"
    },
    {
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": $SS_PORT,
            "method": "$SS_METHOD",
            "password": "$SS_PASSWORD"
          }
        ]
      },
      "tag": "ss_out"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["http_in"],
        "outboundTag": "ss_out"
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
# PHẦN 4: CẤU HÌNH NGINX
#############################################

echo -e "${GREEN}[4/7] Cấu hình và tối ưu Nginx...${NC}"

# Tối ưu cấu hình chính của Nginx
cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 8192;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # Tối ưu buffer
    client_max_body_size 10m;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    
    # Tối ưu timeouts
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;
    
    # Tối ưu gzip
    gzip on;
    gzip_vary on;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_proxied any;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/rss+xml
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/svg+xml
        image/x-icon
        text/css
        text/plain
        text/x-component;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Cấu hình máy chủ Nginx cho V2Ray
cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $PUBLIC_IP;
    
    access_log /var/log/nginx/v2ray-access.log;
    error_log /var/log/nginx/v2ray-error.log;
    
    # Ngụy trang là một trang web bình thường
    location / {
        root /var/www/html;
        index index.html;
        
        # Thêm các HTTP header bảo mật
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;
    }
    
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
        root /var/www/html;
        types { } 
        default_type application/x-ns-proxy-autoconfig;
        
        # Thêm cache headers cho PAC file
        add_header Cache-Control "public, max-age=86400";
    }
}
EOF

# Kích hoạt cấu hình Nginx
ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

#############################################
# PHẦN 5: TẠO PAC FILE VÀ TRANG WEB
#############################################

echo -e "${GREEN}[5/7] Tạo PAC file và trang web ngụy trang...${NC}"

# Tạo thư mục và PAC file
mkdir -p /var/www/html/proxy
cat > /var/www/html/proxy/proxy.pac << EOF
function FindProxyForURL(url, host) {
    // Tối ưu hiệu suất bằng cache
    if (isPlainHostName(host) || 
        dnsDomainIs(host, "local") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    
    // Các domain cần dùng proxy
    var domains = [
        // Mạng xã hội phổ biến
        ".facebook.com", ".fbcdn.net",
        ".twitter.com",
        ".instagram.com",
        ".pinterest.com",
        ".telegram.org",
        ".t.me",
        
        // Google services
        ".google.com", ".googleapis.com", ".gstatic.com", 
        ".youtube.com", ".ytimg.com", ".ggpht.com",
        ".googlevideo.com", ".googleusercontent.com",
        
        // Dịch vụ phổ biến khác
        ".netflix.com", ".nflxvideo.net",
        ".spotify.com",
        ".amazon.com",
        ".twitch.tv",
        ".reddit.com",
        
        // IP/Speed checking
        ".ipleak.net",
        ".speedtest.net",
        ".fast.com"
    ];
    
    // Kiểm tra domain trong danh sách hiệu quả hơn
    var domain = host.toLowerCase();
    for (var i = 0; i < domains.length; i++) {
        if (dnsDomainIs(domain, domains[i]) || 
            shExpMatch(domain, "*" + domains[i])) {
            return "PROXY $PUBLIC_IP:$HTTP_PROXY_PORT";
        }
    }
    
    // Mặc định truy cập trực tiếp
    return "DIRECT";
}
EOF

# Tạo trang web ngụy trang
cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Secure Data Solutions</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;
            margin: 0; 
            padding: 0; 
            line-height: 1.6; 
            color: #333;
            background-color: #f8f9fa;
        }
        .header { 
            background: linear-gradient(135deg, #6a11cb, #2575fc);
            color: white; 
            text-align: center; 
            padding: 60px 0; 
            margin-bottom: 30px;
        }
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
            padding: 0 20px; 
        }
        .features {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin: 40px 0;
        }
        .feature {
            flex: 0 0 30%;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }
        .feature h3 {
            color: #2575fc;
            margin-top: 0;
        }
        .cta {
            background: #f0f0f0;
            padding: 40px 0;
            text-align: center;
            margin: 40px 0;
        }
        .button {
            display: inline-block;
            background: #6a11cb;
            color: white;
            padding: 12px 30px;
            border-radius: 4px;
            text-decoration: none;
            font-weight: bold;
            margin-top: 20px;
        }
        .footer { 
            background: #333; 
            color: white; 
            text-align: center; 
            padding: 30px 0; 
            margin-top: 40px; 
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>SecureData Solutions</h1>
            <p>Mạng lưới bảo mật hàng đầu cho doanh nghiệp và cá nhân</p>
        </div>
    </div>
    
    <div class="container">
        <h2>Dịch vụ của chúng tôi</h2>
        <p>SecureData cung cấp giải pháp bảo mật mạng toàn diện với ưu tiên hàng đầu về bảo mật, độ tin cậy và dễ sử dụng.</p>
        
        <div class="features">
            <div class="feature">
                <h3>Bảo vệ dữ liệu</h3>
                <p>Mã hóa đầu cuối mạnh mẽ bảo vệ thông tin nhạy cảm của bạn khỏi các mối đe dọa.</p>
            </div>
            
            <div class="feature">
                <h3>Giải pháp doanh nghiệp</h3>
                <p>Bảo mật cấp doanh nghiệp với các tính năng bảo mật nâng cao cho tổ chức mọi quy mô.</p>
            </div>
            
            <div class="feature">
                <h3>Sao lưu & Khôi phục</h3>
                <p>Giải pháp sao lưu tự động để giữ an toàn dữ liệu quan trọng khỏi mất mát hoặc hỏng hóc.</p>
            </div>
            
            <div class="feature">
                <h3>Truy cập bảo mật</h3>
                <p>Truy cập an toàn vào mạng nội bộ và dữ liệu từ bất kỳ đâu trên thế giới.</p>
            </div>
            
            <div class="feature">
                <h3>Đa nền tảng</h3>
                <p>Hỗ trợ đầy đủ cho Windows, macOS, iOS, Android và các hệ điều hành Linux.</p>
            </div>
            
            <div class="feature">
                <h3>Hỗ trợ 24/7</h3>
                <p>Đội ngũ chuyên gia của chúng tôi luôn sẵn sàng hỗ trợ bạn mọi lúc, mọi nơi.</p>
            </div>
        </div>
        
        <div class="cta">
            <h2>Sẵn sàng bắt đầu?</h2>
            <p>Tham gia cùng hàng nghìn khách hàng hài lòng đang sử dụng giải pháp bảo mật của SecureData.</p>
            <a href="#" class="button">Liên hệ với chúng tôi</a>
        </div>
    </div>
    
    <div class="footer">
        <div class="container">
            <p>&copy; 2025 SecureData Solutions. Mọi quyền được bảo lưu.</p>
            <p>Chính sách bảo mật | Điều khoản dịch vụ | Liên hệ</p>
        </div>
    </div>
</body>
</html>
EOF

#############################################
# PHẦN 6: TẠO TOOL KIỂM TRA KẾT NỐI
#############################################

echo -e "${GREEN}[6/7] Tạo trang kiểm tra kết nối...${NC}"

# Tạo trang kiểm tra kết nối
cat > /var/www/html/check.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Kiểm tra kết nối</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        h1, h2 {
            color: #2575fc;
        }
        .status {
            font-size: 1.1em;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
        }
        .warning {
            background-color: #fff3cd;
            color: #856404;
        }
        .info {
            background-color: #d1ecf1;
            color: #0c5460;
        }
        button {
            background-color: #2575fc;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1em;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        button:hover {
            background-color: #1a5cbe;
        }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(0,0,0,0.1);
            border-radius: 50%;
            border-top-color: #2575fc;
            animation: spin 1s ease-in-out infinite;
            margin-right: 10px;
            vertical-align: middle;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .connection-info {
            background-color: #e6f3ff;
            border-left: 4px solid #2575fc;
            padding: 15px;
            margin: 20px 0;
        }
        code {
            background-color: #f0f0f0;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <h1>Kiểm tra kết nối proxy</h1>
    
    <div class="card">
        <h2>Thông tin kết nối của bạn</h2>
        <div class="connection-info">
            <p><strong>HTTP Proxy:</strong> $PUBLIC_IP:$HTTP_PROXY_PORT</p>
            <p><strong>PAC URL:</strong> http://$PUBLIC_IP/proxy/proxy.pac</p>
            <p><strong>Shadowsocks:</strong> $PUBLIC_IP:$SS_PORT (Password: $SS_PASSWORD, Method: $SS_METHOD)</p>
        </div>
        
        <h3>Kiểm tra địa chỉ IP</h3>
        <button onclick="checkIP()">Kiểm tra IP của tôi</button>
        <div id="ip-result"></div>
        
        <h3>Kiểm tra DNS</h3>
        <button onclick="checkDNS()">Kiểm tra DNS</button>
        <div id="dns-result"></div>
        
        <h3>Kiểm tra tốc độ kết nối</h3>
        <button onclick="checkSpeed()">Kiểm tra tốc độ</button>
        <div id="speed-result"></div>
    </div>
    
    <div class="card">
        <h2>Hướng dẫn cấu hình</h2>
        
        <h3>Cấu hình trên iPhone/iPad</h3>
        <ol>
            <li>Vào <strong>Settings</strong> > <strong>Wi-Fi</strong></li>
            <li>Chọn mạng Wi-Fi hiện tại (nhấn vào biểu tượng (i))</li>
            <li>Kéo xuống và chọn <strong>Configure Proxy</strong></li>
            <li>Chọn <strong>Automatic</strong> và nhập URL: <code>http://$PUBLIC_IP/proxy/proxy.pac</code></li>
            <li>Hoặc chọn <strong>Manual</strong>, nhập <code>$PUBLIC_IP</code> và cổng <code>$HTTP_PROXY_PORT</code></li>
        </ol>
        
        <h3>Cấu hình Shadowsocks</h3>
        <p>Sử dụng thông tin sau để cấu hình ứng dụng Shadowsocks:</p>
        <ul>
            <li>Địa chỉ máy chủ: <code>$PUBLIC_IP</code></li>
            <li>Cổng: <code>$SS_PORT</code></li>
            <li>Mật khẩu: <code>$SS_PASSWORD</code></li>
            <li>Phương thức mã hóa: <code>$SS_METHOD</code></li>
        </ul>
    </div>
    
    <script>
        function checkIP() {
            const resultDiv = document.getElementById('ip-result');
            resultDiv.innerHTML = '<div class="loading"></div> Đang kiểm tra IP...';
            
            fetch('https://api.ipify.org?format=json')
                .then(response => response.json())
                .then(data => {
                    resultDiv.innerHTML = '<div class="status success">IP hiện tại của bạn: <strong>' + data.ip + '</strong></div>';
                })
                .catch(error => {
                    resultDiv.innerHTML = '<div class="status error">Không thể kiểm tra IP: ' + error.message + '</div>';
                });
        }
        
        function checkDNS() {
            const resultDiv = document.getElementById('dns-result');
            resultDiv.innerHTML = '<div class="loading"></div> Đang kiểm tra DNS...';
            
            fetch('https://1.1.1.1/cdn-cgi/trace')
                .then(response => response.text())
                .then(data => {
                    const lines = data.split('\\n');
                    let ip = '';
                    let location = '';
                    
                    for (const line of lines) {
                        if (line.startsWith('ip=')) {
                            ip = line.substring(3);
                        }
                        if (line.startsWith('loc=')) {
                            location = line.substring(4);
                        }
                    }
                    
                    resultDiv.innerHTML = '<div class="status info">DNS resolve thành công!<br>IP: <strong>' + 
                        ip + '</strong><br>Vị trí: <strong>' + location + '</strong></div>';
                })
                .catch(error => {
                    resultDiv.innerHTML = '<div class="status error">Không thể kiểm tra DNS: ' + error.message + '</div>';
                });
        }
        
        function checkSpeed() {
            const resultDiv = document.getElementById('speed-result');
            resultDiv.innerHTML = '<div class="loading"></div> Đang kiểm tra tốc độ kết nối...';
            
            const startTime = new Date().getTime();
            const imageSize = 2097152; // 2MB image
            
            fetch('https://speed.cloudflare.com/__down?bytes=2097152')
                .then(response => {
                    const endTime = new Date().getTime();
                    const duration = (endTime - startTime) / 1000;
                    const speed = ((imageSize * 8) / duration) / 1000000;
                    
                    resultDiv.innerHTML = '<div class="status success">Tốc độ tải xuống: <strong>' + 
                        speed.toFixed(2) + ' Mbps</strong></div>';
                })
                .catch(error => {
                    resultDiv.innerHTML = '<div class="status error">Không thể kiểm tra tốc độ: ' + error.message + '</div>';
                });
        }
    </script>
</body>
</html>
EOF

#############################################
# PHẦN 7: TẠO SCRIPT BẢO TRÌ VÀ KHỞI ĐỘNG DỊCH VỤ
#############################################

echo -e "${GREEN}[7/7] Tạo script bảo trì và khởi động dịch vụ...${NC}"

# Tạo script giám sát
cat > /usr/local/bin/monitor-proxy.sh << EOF
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "\${YELLOW}Kiểm tra tài nguyên hệ thống:${NC}"
echo -e "CPU: \$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - \$1}')% đang sử dụng"
echo -e "RAM: \$(free -m | awk 'NR==2{printf "%.2f%%", \$3*100/\$2}')"
echo -e "SWAP: \$(free -m | awk 'NR==3{printf "%.2f%%", \$3*100/\$2}')"
echo -e "Dung lượng: \$(df -h / | awk 'NR==2{print \$5}')"

echo -e "\${YELLOW}Kiểm tra dịch vụ:${NC}"
for service in v2ray nginx; do
  if systemctl is-active --quiet \$service; then
    echo -e "\${GREEN}\$service: đang chạy${NC}"
  else
    echo -e "\${RED}\$service: không chạy${NC}"
    systemctl restart \$service
    echo -e "Đã cố gắng khởi động lại \$service"
  fi
done

echo -e "\${YELLOW}Thống kê kết nối:${NC}"
echo "Kết nối HTTP Proxy:"
netstat -anp | grep :$HTTP_PROXY_PORT | wc -l
echo "Kết nối WebSocket:"
netstat -anp | grep :$WS_PORT | wc -l
echo "Kết nối Shadowsocks:"
netstat -anp | grep :$SS_PORT | wc -l

echo -e "\${YELLOW}Kiểm tra kết nối:${NC}"
curl -s -x http://localhost:$HTTP_PROXY_PORT -o /dev/null -w "HTTP Proxy: %{http_code}\n" https://www.google.com

echo -e "\${YELLOW}Kiểm tra log lỗi:${NC}"
tail -n 10 /var/log/v2ray/error.log

# Kiểm tra và khởi động lại nếu có lỗi
error_count=\$(grep -c "error" /var/log/v2ray/error.log 2>/dev/null)
if [ \$error_count -gt 10 ]; then
    echo -e "\${RED}Phát hiện quá nhiều lỗi trong log V2Ray, khởi động lại...${NC}"
    systemctl restart v2ray
fi
EOF
chmod +x /usr/local/bin/monitor-proxy.sh

# Tạo script khởi động lại dịch vụ
cat > /usr/local/bin/restart-proxy.sh << EOF
#!/bin/bash
systemctl restart v2ray
systemctl restart nginx
echo "Tất cả dịch vụ đã được khởi động lại"
EOF
chmod +x /usr/local/bin/restart-proxy.sh

# Tạo script cập nhật tự động
cat > /usr/local/bin/update-proxy.sh << EOF
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "\${GREEN}Đang cập nhật hệ thống...${NC}"
apt update && apt upgrade -y

echo -e "\${GREEN}Đang cập nhật V2Ray...${NC}"
systemctl stop v2ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

echo -e "\${GREEN}Khởi động lại dịch vụ...${NC}"
systemctl daemon-reload
systemctl restart v2ray
systemctl restart nginx

echo -e "\${GREEN}Cập nhật hoàn tất${NC}"
EOF
chmod +x /usr/local/bin/update-proxy.sh

# Tự động khởi động lại dịch vụ mỗi ngày
(crontab -l 2>/dev/null || echo "") | {
    cat
    echo "0 4 * * * /usr/local/bin/restart-proxy.sh > /dev/null 2>&1"
    echo "0 */6 * * * /usr/local/bin/monitor-proxy.sh > /var/log/proxy-monitor.log 2>&1"
} | crontab -

# Thay đổi quyền sở hữu
chown -R nobody:nogroup /var/log/v2ray/
chmod 755 /var/log/v2ray/

# Khởi động dịch vụ
echo -e "${GREEN}Khởi động dịch vụ...${NC}"
systemctl daemon-reload
systemctl enable v2ray
systemctl enable nginx
systemctl restart v2ray
systemctl restart nginx

# Lưu thông tin cấu hình
mkdir -p /etc/v2ray-setup
cat > /etc/v2ray-setup/config.json << EOF
{
  "http_proxy_port": $HTTP_PROXY_PORT,
  "ss_port": $SS_PORT,
  "ss_password": "$SS_PASSWORD",
  "ss_method": "$SS_METHOD",
  "ws_port": $WS_PORT,
  "uuid": "$UUID",
  "ws_path": "$WS_PATH",
  "public_ip": "$PUBLIC_IP",
  "installation_date": "$(date)",
  "note": "Cấu hình HTTP - Shadowsocks Bridge với 2GB RAM ảo"
}
EOF
chmod 600 /etc/v2ray-setup/config.json

# Tạo URL chia sẻ V2Ray
V2RAY_CONFIG=$(cat <<EOF
{
  "v": "2",
  "ps": "V2Ray-WebSocket-SS-Bridge",
  "add": "$PUBLIC_IP",
  "port": "80",
  "id": "$UUID",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "$PUBLIC_IP",
  "path": "$WS_PATH",
  "tls": ""
}
EOF
)

# Mã hóa cấu hình để tạo URL
V2RAY_LINK="vmess://$(echo $V2RAY_CONFIG | jq -c . | base64 -w 0)"

# Tạo link cấu hình Shadowsocks
SS_URI="ss://$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0)@${PUBLIC_IP}:${SS_PORT}"

echo -e "\n${BLUE}========================================================${NC}"
echo -e "${GREEN}CÀI ĐẶT THÀNH CÔNG! HỆ THỐNG ĐÃ ĐƯỢC TỐI ƯU HÓA${NC}"
echo -e "${BLUE}========================================================${NC}"

echo -e "\n${YELLOW}THÔNG TIN KẾT NỐI:${NC}"
echo -e "HTTP Proxy: ${GREEN}$PUBLIC_IP:$HTTP_PROXY_PORT${NC}"
echo -e "Shadowsocks: ${GREEN}$PUBLIC_IP:$SS_PORT${NC}"
echo -e "Shadowsocks Password: ${GREEN}$SS_PASSWORD${NC}"
echo -e "Shadowsocks Method: ${GREEN}$SS_METHOD${NC}"
echo -e "V2Ray WebSocket: ${GREEN}http://$PUBLIC_IP:80$WS_PATH${NC}"
echo -e "UUID: ${GREEN}$UUID${NC}"
echo -e "PAC URL: ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"

echo -e "\n${YELLOW}URL CHIA SẺ:${NC}"
echo -e "V2Ray Link: ${GREEN}$V2RAY_LINK${NC}"
echo -e "Shadowsocks URI: ${GREEN}$SS_URI${NC}"

echo -e "\n${YELLOW}HƯỚNG DẪN SỬ DỤNG TRÊN IPHONE:${NC}"
echo -e "1. Vào Settings > Wi-Fi > [Mạng Wi-Fi] > Configure Proxy > Auto"
echo -e "2. URL: ${GREEN}http://$PUBLIC_IP/proxy/proxy.pac${NC}"
echo -e "3. Hoặc cấu hình thủ công: Proxy: ${GREEN}$PUBLIC_IP${NC} Port: ${GREEN}$HTTP_PROXY_PORT${NC}"

echo -e "\n${YELLOW}TRANG KIỂM TRA:${NC}"
echo -e "URL: ${GREEN}http://$PUBLIC_IP/check.html${NC}"

echo -e "\n${YELLOW}QUẢN LÝ HỆ THỐNG:${NC}"
echo -e "Giám sát: ${GREEN}sudo /usr/local/bin/monitor-proxy.sh${NC}"
echo -e "Khởi động lại: ${GREEN}sudo /usr/local/bin/restart-proxy.sh${NC}"
echo -e "Cập nhật: ${GREEN}sudo /usr/local/bin/update-proxy.sh${NC}"

echo -e "\n${GREEN}RAM ảo 2GB và tối ưu hóa hệ thống đã được thiết lập!${NC}"
echo -e "${BLUE}========================================================${NC}"

# Kiểm tra trạng thái dịch vụ
sleep 3
echo -e "\n${YELLOW}Kiểm tra trạng thái dịch vụ:${NC}"
systemctl status v2ray --no-pager | grep Active || echo "V2Ray không chạy!"
systemctl status nginx --no-pager | grep Active || echo "Nginx không chạy!"
