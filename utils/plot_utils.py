from evm_cfg_builder.cfg.basic_block import BasicBlock
from evm_cfg_builder.cfg import CFG
from graphviz import Digraph, Source

from utils.cmd_utils import run_cmd


def plot_cfg_with_target(_cfg: CFG, contract_name):
    """
    输出cfg的可视化图像，用红色标记原始漏洞，蓝色标记传染路径
    :param _cfg:
    :return:
    """
    already_visited = set()
    dot = Digraph(comment='CFG with target')
    # for each_bb in _cfg.basic_blocks:
    #     dot.node(str(each_bb.start.pc),penwidth="0.5", style='dotted')
    bb = _cfg.entry_point
    recursion_plot(bb, dot, already_visited,True)
    dot.render(f'target_file/cfg_with_target_{contract_name}.dot', view=False)
    run_cmd(f"dot -Gdpi=500 -Tpng target_file/cfg_with_target_{contract_name}.dot -o {contract_name}_target.png")


def recursion_plot(_bb: BasicBlock, _dot: Digraph, _already_visited, target_view_model=True):
    if _bb.start.pc in _already_visited:
        return
    else:
        _already_visited.add(_bb.start.pc)
    if target_view_model:
        if _bb.bug:
            if _bb.start.pc == 0x55b:
                _dot.node(str(_bb.start.pc), color='green', penwidth="3.0",style="solid")
            else:
                if _bb.original_bug:
                    _dot.node(str(_bb.start.pc), color='red', penwidth="3.0",style="solid")
                else:
                    _dot.node(str(_bb.start.pc), color='blue', penwidth="3.0",style="solid")
        else:
            _dot.node(str(_bb.start.pc), penwidth="0.5", style='dotted')
    else:
        _dot.node(str(_bb.start.pc))
    for next_bb in _bb.all_outgoing_basic_blocks:
        if target_view_model:
            if _bb.bug and next_bb.bug:
                _dot.edge(str(_bb.start.pc), str(next_bb.start.pc), penwidth="3.0")
            else:
                _dot.edge(str(_bb.start.pc), str(next_bb.start.pc), penwidth="0.5", style='dotted')
        else:
            _dot.edge(str(_bb.start.pc), str(next_bb.start.pc))
        recursion_plot(next_bb, _dot, _already_visited, target_view_model)


def plot_cfg_use_evm_cfg_builder(_cfg: CFG):
    """
    使用evm_cfg_builder生成的CFG,该图不包含bug信息
    :param _output_dir:
    :param _cfg:
    :return:
    """
    _output_dir = "target_file"
    _cfg.output_to_dot(_output_dir + "/cfg_origin")
    with open(_output_dir + "/cfg_originFULL_GRAPH.dot", 'r') as f:
        dot_str = f.read()
        dot = Source(dot_str)
        dot.render(f'{_output_dir}/cfg_origin.gv', view=False)


def plot_cfg_without_target(_cfg: CFG, contract_name):
    """
    :param _cfg:
    :return:
    """
    already_visited = set()
    dot = Digraph(comment='CFG without target')
    # for each_bb in _cfg.basic_blocks:
    #     dot.node(str(each_bb.start.pc),penwidth="0.5", style='solid')
    bb = _cfg.entry_point
    recursion_plot(bb, dot, already_visited, False)
    dot.render(f'target_file/cfg_without_target_{contract_name}.gv', view=False)
    run_cmd(f"dot -Gdpi=500 -Tpng target_file/cfg_without_target_{contract_name}.gv -o {contract_name}_no_target.png")
