import logging
import os

class Config:
    def __init__(self):
        # 日志设置……
        self.log_file = 'log.txt'
        if os.path.exists(self.log_file):
            open(self.log_file, 'w').close()
        logging.basicConfig(
            filename=self.log_file, level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        # 规则目录设置……
        self.rule_dir = './rule'
        self.source_dir = './source'
        self.singbox_output_directory = os.path.join(self.rule_dir, 'singbox')
        self.clash_output_directory   = os.path.join(self.rule_dir, 'clash')
        # ……其他输出目录略

        # 类型映射（已有）
        self.map_dict = {
            'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain',
            'DOMAIN-KEYWORD': 'domain_keyword', 'DOMAIN-REGEX': 'domain_regex',
            'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'GEOIP': 'geoip',
            # ……其余映射
        }
        self.MAP_REVERSE = {v: k for k, v in self.map_dict.items()}

        # ——新增—— 允许的类型集合
        # 1) geosite 只保留域名相关的
        self._geosite_types = {
            'domain', 'domain_suffix',
            'domain_keyword', 'domain_regex'
        }
        # 2) geoip 只保留 IP/CIDR/GeoIP 相关的
        self._geoip_types = {
            'ip_cidr', 'source_ip_cidr', 'geoip'
        }

        # Clash/Surge 映射（可定制）
        self.SINGBOX_TO_CLASH_MAP = {
            k: self.MAP_REVERSE[k] for k in self._geosite_types.union(self._geoip_types)
        }
        # 如果 Surge 也需要同样过滤，可以同理构造：
        self.SINGBOX_TO_SURGE_MAP = dict(self.SINGBOX_TO_CLASH_MAP)

    def filter_rules(self, rules: list[dict], mode: str) -> list[dict]:
        """
        根据 mode ('geosite' or 'geoip') 过滤规则列表。
        每个 rule 应包含 'type' 字段，对应 map_dict 的 value。
        """
        if mode == 'geosite':
            allowed = self._geosite_types
        elif mode == 'geoip':
            allowed = self._geoip_types
        else:
            return []

        return [rule for rule in rules if rule['type'] in allowed]


# ——调用示例——
# 假设你已经把 .srs 解析成了列表 rules，每项类似：
#   {'type': 'domain_suffix', 'value': 'example.com'}
# 那么分别这样输出：
cfg = Config()
all_rules = [
    {'type': 'domain', 'value': 'foo.com'},
    {'type': 'ip_cidr', 'value': '1.2.3.0/24'},
    {'type': 'geoip', 'value': 'CN'},
    {'type': 'domain_keyword', 'value': 'ad'}
]

# 生成 geosite.json 的内容，只会留下 domain/domain_suffix/...：
geo_rules = cfg.filter_rules(all_rules, mode='geosite')
# 生成 geoip.json 的内容，只会留下 ip_cidr/source_ip_cidr/geoip：
ip_rules  = cfg.filter_rules(all_rules, mode='geoip')

print("Geosite:", geo_rules)
print("GeoIP:", ip_rules)
