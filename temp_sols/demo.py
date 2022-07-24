import time
import evm_cfg_builder
from crytic_compile import CryticCompile
from graphviz import Digraph, Source
import os
from slither import Slither


cy = CryticCompile("temp_sols/sol1.sol")
sl = Slither("temp_sols/sol1.sol")
cfg = evm_cfg_builder.CFG(cy.compilation_units['temp_sols/sol1.sol'].bytecodes_runtime['BlocklancerToken'])
cfg.output_to_dot("sc_")
with open("sc_FULL_GRAPH.dot", 'r') as f:
    dot_str = f.read()
    dot = Source(dot_str)
    dot.render(f'cfg_origin.gv', view=False)


# deep_plot_visited = set()
# dot = Digraph(comment='CFG', node_attr={'shape': 'record','fontname': 'SimHei'})


# def deep_plot(bb):
#     if bb not in deep_plot_visited:
#         deep_plot_visited.add(bb)
#     else:
#         return
#     if bb.start.pc > 0x6e:
#         return
#     ins_str = '<f0> '
#     for ins in bb.instructions:
#         ins_str += ""
#         name = ins.name
#         operand = ins.operand
#         if operand is not None:
#             ins_str += f'{hex(ins.pc)} {name} {hex(operand)}'
#         else:
#             ins_str += f'{hex(ins.pc)} {name}'
#         ins_str += r'\l'
#     content = ""
#     if bb.start.pc == 0x0:
#         content = r"合约初始化\l"
#     elif bb.start.pc == 0xd:
#         content = r"判断外界请求调用的函数签名\l0xeecae21为draw()的函数签名\l"
#     elif bb.start.pc == 0x46:
#         content = r"判断此次外部调用是否携带以太币\l由于函数没有payable关键字\l因此携带以太币跳转至异常处理基本块0x4e\l"
#     elif bb.start.pc == 0x4e:
#         content = r"回滚本次调用\l"
#     elif bb.start.pc == 0x52:
#         content = r"draw函数初始化\l"
#     elif bb.start.pc == 0x5d:
#         content = r"执行draw函数\l获得当前区块时间戳\l跳转至payOut函数\l"
#     elif bb.start.pc == 0x41:
#         content = r"合约初始化失败\l"
#     elif bb.start.pc == 0x6e:
#         content = r"执行payout函数第1行的if语句\l"
#     ins_str += f"|<f1> {content}"
#     print(ins_str)
#     if bb.start.pc == 0x5d:   
#         dot.node(str(bb.start.pc), label=ins_str,color='blue',penwidth="3")
#     elif bb.start.pc == 0x6e or bb.start.pc == 121 or bb.start.pc == 130:
#         dot.node(str(bb.start.pc), label=ins_str,color='red',penwidth="3")
#     else:
#         dot.node(str(bb.start.pc), label=ins_str)
#     for outgoing_bb in bb.all_outgoing_basic_blocks:
#         dot.edge(str(bb.start.pc), str(outgoing_bb.start.pc))
#         deep_plot(outgoing_bb)


# deep_plot(cfg.entry_point)
# dot.render(f'cfg_deep.gv', view=False)
# os.popen("dot -Gdpi=500 -Tpng cfg_deep.gv -o cfg_deep.png")


asms = os.popen("solc --asm --bin-runtime temp_sols/sol1.sol").readlines()
open("asm.txt", "w").writelines(asms)

# time1 = time.time()
# output = os.popen(cmd="myth -v 5 analyze sol1.sol:JavaSwapTest -o json > report.json").readlines()
# time2 = time.time()
# print(output)
# print(f"mythril消耗了:{time2-time1}")

path = set()
visited = set()
counter = {}


def deep(bb):
    if bb in visited:
        return
    else:
        visited.add(bb)
    for outgoing_bb in bb.all_outgoing_basic_blocks:
        path.add((bb, outgoing_bb))
        deep(outgoing_bb)


for name, bytecode in cy.compilation_units['temp_sols/sol1.sol'].bytecodes_runtime.items():
    path = set()
    visited = set()
    try:
        cfg = evm_cfg_builder.CFG(bytecode)
        deep(cfg.entry_point)
        counter[name] = {"bb": len(visited), "path": len(path)}
    except BaseException as e:
        counter[name] = {"bb": 0, "path": 0}
print(counter)
