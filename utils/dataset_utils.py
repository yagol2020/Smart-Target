"""
数据集工具类
"""
import os
from typing import List

import loguru
import pandas as pd

from utils import cmd_utils, solc_utils
from utils.solc_utils import compile_sol

dataset_map_path = "/home/yagol/Desktop/Smart-Target/dataset_manticore_only_reentranct.csv"
dataset_map = pd.read_csv(dataset_map_path)


def get_dataset():
    """
    获取数据集
    :return:
    """
    """
    排除掉name为空的数据，因为这些数据还没有主contract名字和solc版本
    将结果升序排列，先检查文件大小比较小的，这样比较快
    """
    return dataset_map[
        # (dataset_map['enable'])
        # & (dataset_map['slither_time'].isnull())
        (dataset_map['manticore_target_time'].isnull())
        # & (dataset_map['manticore_fully_time'].isnull())
        ].sort_values(by='size', ascending=True)


def get_finished_dataset():
    """
    获取已完成的数据集
    :return:
    """
    return dataset_map[
        (dataset_map['enable'])
        & (dataset_map['slither_time'].notnull())
        # & (dataset_map['manticore_target_time'].notnull())
        & (dataset_map['manticore_fully_time'].notnull())
        ].sort_values(by='size', ascending=True)


def update_slither_and_no_bug_reason(index, slither_time, no_bug_reason, line_map):
    dataset_map.loc[index, 'slither_time'] = slither_time
    dataset_map.loc[index, 'enable'] = False
    dataset_map.loc[index, 'enable_reason'] = no_bug_reason
    dataset_map.loc[index, 'line'] = line_map
    dataset_map.to_csv(dataset_map_path, index=False)


def update_target_manticore_and_no_bug_reason(index, no_bug_reason):
    dataset_map.loc[index, 'enable'] = False
    dataset_map.loc[index, 'enable_reason'] = no_bug_reason
    dataset_map.to_csv(dataset_map_path, index=False)


def update_fully_manticore_and_no_bug_reason(index, no_bug_reason):
    dataset_map.loc[index, 'enable'] = False
    dataset_map.loc[index, 'enable_reason'] = no_bug_reason
    dataset_map.to_csv(dataset_map_path, index=False)


def update_slither_time(index, slither_time, slither_result, line_map):
    dataset_map.loc[index, 'slither_time'] = slither_time
    dataset_map.loc[index, 'slither_result'] = slither_result
    dataset_map.loc[index, 'line'] = line_map
    dataset_map.to_csv(dataset_map_path, index=False)


def update_manticore_target_time(index, manticore_target_time, manticore_target_result, findings, line_map):
    dataset_map.loc[index, 'manticore_target_time'] = manticore_target_time
    dataset_map.loc[index, 'manticore_target_result'] = manticore_target_result
    dataset_map.loc[index, 'manticore_target_findings'] = findings
    dataset_map.loc[index, 'line'] = line_map
    dataset_map.to_csv(dataset_map_path, index=False)


def update_manticore_fully_time(index, manticore_fully_time, manticore_fully_result, findings, line_map):
    dataset_map.loc[index, 'manticore_fully_time'] = manticore_fully_time
    dataset_map.loc[index, 'manticore_fully_result'] = manticore_fully_result
    dataset_map.loc[index, 'manticore_fully_findings'] = findings
    dataset_map.loc[index, 'line'] = line_map
    dataset_map.to_csv(dataset_map_path, index=False)
