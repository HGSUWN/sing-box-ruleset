import logging
import os

class Config:
    def __init__(self):
        # 日志设置
        self.log_file = 'log.txt'
        if os.path.exists(self.log_file):
            open(self.log_file, 'w').close()  # 清空旧的日志内容

        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        # 路径设置
        self.rule_dir = './rule'
        self.source_dir = './source'

        # 各平台输出目录
        self.singbox_output_directory = os.path.join(self.rule_dir, 'singbox')
        self.surge_output_directory = os.path.join(self.rule_dir, 'surge')
        self.shadowrocket_output_directory = os.path.join(self.rule_dir, 'shadowrocket')
        self.clash_output_directory = os.path.join(self.rule_dir, 'clash')

        # 其他选项
        self.trust_upstream = False
        self.ls_index = 1
        self.enable_trie_filtering = True  # 是否按照 domain_suffix 剔除重复的 domain
        self.ls_keyword = ['little-snitch', 'adobe-blocklist']  # little snitch 链接关键字
        self.adg_keyword = ['adguard']  # adguard 链接关键字

        # 原始类型到内部字段映射
        self.map_dict = {
            'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix',
            'DOMAIN': 'domain', 'HOST': 'domain',
            'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword',
            'URL-REGEX': 'domain_regex', 'DOMAIN-REGEX': 'domain_regex',
            'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr',
            'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip',
            'DST-PORT': 'port', 'SRC-PORT': 'source_port', 'PROCESS-NAME': 'process_name'
        }
        # 反向映射
        self.MAP_REVERSE = {v: k for k, v in self.map_dict.items()}

        # 允许生成到 geosite 的内部字段
        self.GEOSITE_ALLOW = {
            'domain', 'domain_suffix', 'domain_keyword', 'domain_regex'
        }
        # 允许生成到 geoip 的内部字段
        self.GEOIP_ALLOW = {
            'ip_cidr', 'source_ip_cidr'
        }

        # 平台映射
        self.SINGBOX_TO_CLASH_MAP = {
            'domain_suffix': 'DOMAIN-SUFFIX',
            'domain': 'DOMAIN',
            'domain_keyword': 'DOMAIN-KEYWORD',
            'domain_regex': 'DOMAIN-REGEX',
            'ip_cidr': 'IP-CIDR',
            'source_ip_cidr': 'SRC-IP-CIDR',
            'geoip': 'GEOIP',
            'port': 'DST-PORT',
            'source_port': 'SRC-PORT',
            'process_name': 'PROCESS-NAME'
        }
        self.SINGBOX_TO_SURGE_MAP = dict(self.SINGBOX_TO_CLASH_MAP)

    def collect_sources(self, all_rules: dict, kind: str) -> list:
        """
        根据类型过滤出 geosite 或 geoip 的规则源 URL 列表并去重。

        :param all_rules: 原始规则字典，格式举例:
                          {'DOMAIN-SUFFIX': [...], 'IP-CIDR': [...], 'GEOIP': [...]}
        :param kind: 'geosite' 或 'geoip'
        :return: 过滤并去重后的 URL 列表
        """
        out = []
        for raw_type, urls in all_rules.items():
            internal = self.map_dict.get(raw_type)
            if not internal:
                continue
            # 根据 kind 过滤内部字段
            if kind == 'geosite' and internal not in self.GEOSITE_ALLOW:
                continue
            if kind == 'geoip' and internal not in self.GEOIP_ALLOW:
                continue
            # 符合条件，加入列表
            out.extend(urls)
        # 去重并保序
        return list(dict.fromkeys(out))


# 示例用法
if __name__ == '__main__':
    cfg = Config()
    # 模拟读取到的规则源
    all_rules = {
        'DOMAIN-SUFFIX': ['https://example.com/geosite-cn.srs'],
        'IP-CIDR': ['https://example.com/cn-ip.srs'],
        'GEOIP': ['https://example.com/cn-geoip.srs'],
    }

    geosite_urls = cfg.collect_sources(all_rules, 'geosite')
    geoip_urls = cfg.collect_sources(all_rules, 'geoip')

    print('Geosite URLs:', geosite_urls)
    print('GeoIP URLs:', geoip_urls)
