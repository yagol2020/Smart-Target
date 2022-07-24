"""
从smartbugs数据集中, 获得漏洞所在的行数等信息, 用于构成漏洞目标

"""
import json

import loguru

from utils.slither_utils import BugInfo


SMART_BUGS_INFO_PATH = "/root/smartbugs/dataset/vulnerabilities.json"


def find_start_length_content_by_line_num(_sl, _line_num, _file_content):
    for c in _sl.contracts:
        for f in c.functions:
            if _line_num == f.source_mapping['lines'][0]:
                loguru.logger.debug(f"该漏洞位于函数声明位置,{_line_num}行,也就是函数的第一行")
                start = f.source_mapping['start']
                length = f.source_mapping['length']
                content = _file_content[start:start+length]
                return start, length, content, start, length, content, _line_num
            for e in f.expressions:
                if _line_num in e.source_mapping['lines']:
                    if len(e.source_mapping['lines']) != 1:
                        loguru.logger.warning(
                            f"搜索{_line_num}行的漏洞时, 发现该行存在的表达式可能存在跨行行为")
                    start = e.source_mapping['start']
                    length = e.source_mapping['length']
                    content = _file_content[start:start+length]
                    f_start = f.source_mapping['start']
                    f_length = f.source_mapping['length']
                    f_content = _file_content[f_start:f_start+f_length]
                    f_line_num = f.source_mapping['lines'][0]
                    return start, length, content, f_start, f_length, f_content, f_line_num
    return None, None, None, None, None, None, None


def get_smart_bugs_info(_sol_path, _sl):
    file_content = open(_sol_path, 'r').read()
    res = dict()
    smart_bug_infos = json.load(open(SMART_BUGS_INFO_PATH, "r"))
    for one_smart_bug in smart_bug_infos:
        if one_smart_bug['path'] == _sol_path.replace('/root/smartbugs/', ''):
            for vulns in one_smart_bug['vulnerabilities']:
                category = vulns['category']
                for bug_line in vulns['lines']:
                    bug_type = category
                    line_num = bug_line
                    start_pos, length, content, f_start, f_length, f_content, f_line_num = find_start_length_content_by_line_num(_sl, line_num, file_content)
                    if start_pos is None:
                        continue  # 这个漏洞行数找不到
                    if start_pos == None or length == None or content == None:
                        loguru.logger.error(f"{_sol_path},{line_num}找不到对应的源代码位置,跳过")
                        continue
                    if f_start == None or f_length == None or f_content == None or f_line_num == None:
                        loguru.logger.error(f"{_sol_path},{line_num}找不到对应的函数签名的位置,跳过")
                        continue
                    slither_node = {}
                    slither_addtional_field = {}
                    func_info = BugInfo(f_start, f_length, f_content, "function_sig", f_line_num, slither_node, slither_addtional_field)
                    info = BugInfo(start_pos, length, content, bug_type, line_num, slither_node, slither_addtional_field, True, func_info)
                    if line_num not in res.keys():
                        res[line_num] = [info]
                    else:
                        res[line_num].append(info)
    return res


def get_people_bugs_info(_sol_path, _sl, _bug_lines, _category):
    """
    从_bug_lines中获得漏洞行号, 获得漏洞所在的位置

    """
    file_content = open(_sol_path, 'r').read()
    res = dict()
    for bug_line in _bug_lines:
        bug_type = _category
        line_num = bug_line
        start_pos, length, content, f_start, f_length, f_content, f_line_num = find_start_length_content_by_line_num(_sl, line_num, file_content)
        if start_pos is None:
            loguru.logger.error(f"{bug_line}找不到")
            continue  # 这个漏洞行数找不到
        if start_pos == None or length == None or content == None:
            loguru.logger.error(f"{_sol_path},{line_num}找不到对应的源代码位置,跳过")
            continue
        if f_start == None or f_length == None or f_content == None or f_line_num == None:
            loguru.logger.error(f"{_sol_path},{line_num}找不到对应的函数签名的位置,跳过")
            continue
        slither_node = {}
        slither_addtional_field = {}
        func_info = BugInfo(f_start, f_length, f_content, "function_sig", f_line_num, slither_node, slither_addtional_field)
        # 为了生成cfg, 暂时关闭func_info
        info = BugInfo(start_pos, length, content, bug_type, line_num, slither_node, slither_addtional_field, True)
        if line_num not in res.keys():
            res[line_num] = [info]
        else:
            res[line_num].append(info)
    if len(res)==0:
        loguru.logger.error("没有定位到漏洞")
        raise Exception("没有定位到漏洞")
    return res
