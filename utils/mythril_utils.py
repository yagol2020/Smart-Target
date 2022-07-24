import json
import time
import timeout_decorator
from utils import cmd_utils
import loguru


@timeout_decorator.timeout(10*60*60)  # 10小时
def run_mythril(log_level, sol_path, contract_name, output_dir, solc_version, time_out_mythril_inner=8*60*60, json_path=None):
    """
    time_out_mythril_inner 应该严格小于timeout_decorator的时间.前者是mythril内部的时间, 后者是smart_target工具的时间.

    """
    target_json = json.load(open(f"{output_dir}/target.json", "r"))
    target_json['output_dir'] = output_dir  # 告知mythril输出目录，以便输出分析结果，比如覆盖率
    target_json['is_create'] = False  # 在创建合约之前，不应该跳过指令
    with open(f"{output_dir}/target.json", "w") as f:
        json.dump(target_json, f)
    try:
        time1 = time.time()
        cmd_utils.run_cmd(
            f"myth -v {log_level} -y {output_dir}/target.json analyze --solv {solc_version} --execution-timeout {time_out_mythril_inner} {sol_path}:{contract_name} -o json > {output_dir}/mythril_output_target.json")
        time2 = time.time()
        json_content = json.load(open(json_path, "r"))
        json_content['mythril_with_target'] = time2-time1
        json.dump(json_content, open(json_path, "w"))
    except timeout_decorator.TimeoutError as t_out_e:
        loguru.logger.error(
            f"mythil target 超时{sol_path}:{contract_name}: {t_out_e}")
        json_content = json.load(open(json_path, "r"))
        json_content['mythril_with_target'] = -1
        json_content['target_time_out'] = False
        json.dump(json_content, open(json_path, "w"))


@timeout_decorator.timeout(10*60*60)  # 10小时
def run_mythril_without_target(log_level, sol_path, contract_name, output_dir, solc_version, time_out_mythril_inner=8*60*60, json_path=None):
    with open(f"{output_dir}/fully.json", "w") as f:
        json.dump({"target": False, "output_dir": output_dir,
                  'is_create': False}, f)
    try:
        time1 = time.time()
        cmd_utils.run_cmd(
            f"myth -v {log_level} -y {output_dir}/fully.json analyze --solv {solc_version} --execution-timeout {time_out_mythril_inner} {sol_path}:{contract_name} -o json > {output_dir}/mythril_output_fully.json")
        time2 = time.time()
        json_content = json.load(open(json_path, "r"))
        json_content['mythril_fully'] = time2-time1
        json.dump(json_content, open(json_path, "w"))
    except timeout_decorator.TimeoutError as t_out_e:
        loguru.logger.error(
            f"mythil fully 超时{sol_path}:{contract_name}: {t_out_e}")
        json_content = json.load(open(json_path, "r"))
        json_content['mythril_fully'] = -1
        json_content['fully_time_out'] = False
        json.dump(json_content, open(json_path, "w"))
