from app.utils import get_logger
logger = get_logger()

# 解析规则，只有或，且条件不能出现=

'''
html
title
headers
favicon_hash
'''


def parse_human_rule(rule):
    rule_map = {
        "html": [],
        "title": [],
        "headers": [],
        "favicon_hash": []
    }
    key_map = {
        "body": "html",
        "title": "title",
        "header": "headers",
        "icon_hash": "favicon_hash"
    }
    split_result = rule.split("||")
    empty_flag = True

    for item in split_result:
        key_value = item.split("=")
        key = key_value[0]
        key = key.strip()
        if len(key_value) == 2:
            if key not in key_map:
                logger.info("{} 不在指定关键字中".format(key))
                continue

            value = key_value[1]
            value = value.strip()
            if len(value) <= 6:
                logger.info("{} 长度少于7".format(value))
                continue

            if value[0] != '"' or value[-1] != '"':
                logger.info("{} 没有在双引号内".format(value))
                continue

            empty_flag = False

            # 防御性转换成gbk
            value.encode("gbk")

            value = value[1:-1]
            if key == "icon_hash":
                value = int(value)

            rule_map[key_map[key]].append(value)

    if empty_flag:
        return None

    return rule_map


def transform_rule_map(rule):
    key_map = {
        "html": "body",
        "title": "title",
        "headers": "header",
        "favicon_hash": "icon_hash"
    }
    human_rule_list = []
    for key in rule:
        if key not in key_map:
            logger.info("{} 不在指定关键字中".format(key))
            continue

        for rule_item in rule[key]:
            human_rule_list.append('{}="{}"'.format(key_map[key], rule_item))

    return " || ".join(human_rule_list)
