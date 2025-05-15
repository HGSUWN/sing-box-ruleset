import logging
import os

class Config:
    def __init__(self):
        # 日志设置
        self.log_file = 'log.txt'
        if os.path.exists(self.log_file):
            open(self.log_file, 'w').close()

        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        # 目录设置
        self.rule_dir = './rule'
        self.source_dir = './source'
        
        # 输出目录
        self.singbox_output_directory = os.path.join(self.rule_dir, 'singbox')
        self.clash_output_directory = os.path.join(self.rule_dir, 'clash')
        
        # 核心分类配置 --------------------------------------------------------
        # 地理围栏规则类型（仅域名相关）
        self.geosite_types = {
            'domain',          # 完全匹配
            'domain_suffix',   # 后缀匹配
            'domain_keyword',  # 关键字匹配
            'domain_regex'     # 正则匹配
        }
        
        # IP规则类型（仅IP/CIDR相关）
        self.geoip_types = {
            'ip_cidr',         # IPv4/IPv6 CIDR
            'ip_cidr6',        # IPv6 CIDR（兼容别名）
            'source_ip_cidr',  # 源IP匹配
            'geoip'            # 国家代码
        }

        # 类型映射体系 --------------------------------------------------------
        # 原始类型标准化映射
        self.map_dict = {
            # 域名类型
            'DOMAIN-SUFFIX': 'domain_suffix',
            'HOST-SUFFIX': 'domain_suffix',
            'DOMAIN': 'domain',
            'HOST': 'domain',
            'DOMAIN-KEYWORD': 'domain_keyword',
            'HOST-KEYWORD': 'domain_keyword',
            'URL-REGEX': 'domain_regex',
            'DOMAIN-REGEX': 'domain_regex',
            
            # IP类型
            'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr',
            'IP-CIDR6': 'ip_cidr6',
            'IP6-CIDR': 'ip_cidr6',
            'SRC-IP-CIDR': 'source_ip_cidr',
            'GEOIP': 'geoip',
            
            # 其他（端口、进程等）
            'DST-PORT': 'port',
            'SRC-PORT': 'source_port',
            "PROCESS-NAME": "process_name"
        }

        # 逆向映射
        self.MAP_REVERSE = {v: k for k, v in self.map_dict.items()}

        # 输出映射规则（严格分类）--------------------------------------------
        # Singbox -> Clash 的映射
        self.SINGBOX_TO_CLASH_GEOSITE = {
            # 域名类型映射
            'domain_suffix': 'DOMAIN-SUFFIX',
            'domain': 'DOMAIN',
            'domain_keyword': 'DOMAIN-KEYWORD',
            'domain_regex': 'DOMAIN-REGEX'
        }
        
        self.SINGBOX_TO_CLASH_GEOIP = {
            # IP类型映射
            'ip_cidr': 'IP-CIDR',
            'ip_cidr6': 'IP-CIDR6',
            'source_ip_cidr': 'SRC-IP-CIDR',
            'geoip': 'GEOIP'
        }

        # 其他配置参数
        self.trust_upstream = False
        self.ls_index = 1
        self.enable_trie_filtering = True  # 启用域名后缀去重
