import os
from typing import List

import loguru
import pandas as pd

from utils import solc_utils
from utils.solc_utils import compile_sol


def auto_get_solc_version(path):
    """
    自动获取solc版本
    :param path:
    :return:
    """
    res = ""
    with open(path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.strip().startswith("pragma solidity"):
                res = line.strip().split(" ")[2].replace(";", "").replace(">", "").replace("=", "").replace("<",
                                                                                                            "").replace(
                    "^", "").replace("00", "0").strip()
                break
    if res.count(".") != 2:
        res = ""
    if res == '0.4.2':
        res = ""
    if res == '0.4.4':
        res = ""
    if res == '0.4.0':
        res = ""
    if res == "0.4.8":
        res = ""
    if res == "0.4.9":
        res = ""
    return res


def auto_get_contract_name_and_solc_version(path) -> [str, List[str]]:
    """
    自动获取合约名称和solc版本
    :param path:
    :return:
    """
    solc_version = auto_get_solc_version(path)
    if solc_version == "":  # 没有获得solc版本
        solc_version = "0.4.24"  # 时候使用默认的solc版本
    solc_utils.change_solc_version(solc_version, _print=False)
    try:
        cy = compile_sol(path)
    except BaseException as e:
        loguru.logger.warning(f"{path}编译错误")
        return "no solc", ['']
    contract_name_list = []
    for i in cy.compilation_units[path].contracts_names_without_libraries:
        contract_name_list.append(i)
    return solc_version, contract_name_list


def init():
    df = pd.DataFrame(
        columns=['source', 'path', 'name', 'line', 'solc', 'size', 'enable', 'enable_reason',
                 'slither_time', 'manticore_target_time', 'manticore_fully_time',
                 'slither_result', 'manticore_target_result', 'manticore_fully_result',
                 'manticore_target_findings', 'manticore_fully_findings'])
    origin_sol_files_path = [
        # ('scbs', '/home/yagol/sols_dataset/Smart-Contract-Benchmark-Suites'),
        # ('smartbugs', '/home/yagol/sols_dataset/smartbugs'),
        # ('manticore', "/home/yagol/PycharmProjects/Smart-Target/manticore_target/tests/ethereum/contracts/detectors"),
        # ('smart_bugs_curated', "/home/yagol/Desktop/Smart-Target/data_sets/smart_bugs_Curated"),
        ("smart_bugs_curated_2", "/home/yagol/Desktop/Smart-Target/data_sets/smart_bugs_Curated/reentrancy"),
    ]
    count = 0
    for dataset_name, path in origin_sol_files_path:
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".sol"):
                    sol_file_path = os.path.join(root, file)
                    loguru.logger.info(f"正在分析{sol_file_path}")
                    solc_version, contract_name_list = auto_get_contract_name_and_solc_version(sol_file_path)
                    if solc_version == "no solc" or len(contract_name_list) == 0:
                        loguru.logger.warning(f"{sol_file_path}不能被添加到数据集")
                        continue
                    for contract_name in contract_name_list:
                        if contract_name == 'LogFile' or contract_name == "Log" or contract_name == "attack":
                            continue
                        df = pd.concat([df, pd.DataFrame({
                            'source': [dataset_name],  # 源代码来源
                            'path': [sol_file_path],  # 源代码绝对地址
                            'name': [contract_name],  # 合约名称
                            'line': [''],  # 合约所在的行数
                            'solc': [solc_version],  # solc版本
                            'size': [os.path.getsize(sol_file_path)],  # 源代码大小
                            "enable": [True],  # 是否启用
                            "enable_reason": [""],  # 被关闭原因
                            'slither_time': [''],  # slither执行时间
                            'manticore_target_time': [''],  # 目标执导动态分析执行时间
                            'manticore_fully_time': [''],  # 全量动态分析执行时间
                            'slither_result': [''],  # slither执行结果，json格式
                            'manticore_target_result': [''],  # 目标执行结果，set格式
                            'manticore_fully_result': [''],  # 全量执行结果，set格式
                            'manticore_target_findings': [''],  # 目标执行结果，json格式
                            'manticore_fully_findings': ['']  # 全量执行结果，json格式
                        })], ignore_index=True)
                    count += 1
                    loguru.logger.info(f"{count}个文件已添加到数据集")
    print(df)
    df.to_csv("/home/yagol/Desktop/Smart-Target/dataset_manticore_only_reentranct.csv", index=False)


init()
