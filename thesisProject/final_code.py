import os
import pickle
import angr
import re
import pandas as pd
import numpy as np
import eval_utils as utils
import multiprocessing

def handle_op(project, op_str, cur_addr, func):#1. 若为rip寻址将地址偏移量换成int
    ## 2将有对应string的替换成string
    # addr is memory address
    str_addrs = set([int(addr) for addr, string in func.string_references()])
    #
    op_str = op_str.replace(',', '')
    op_str = op_str.replace('*', ' * ')
    op_str = op_str.replace('ptr', '')
    # [] space and solve mem addr
    if('[' in op_str):  # 相对地址变绝对地址
        pattern = re.compile(r'.*(\[rip\s*\+\s*(\S+)h\])')
        match = pattern.match(op_str)
        if(match):  # rip相对寻址的操作，变成string符号形式
            offset = int(match.group(2), 16)
            # print(f'offset:{offset}')
            try:
                cur_state = project.factory.blank_state(addr=cur_addr)
                cur_rip = int(cur_state.regs.rip._model_concrete.value) #当前状态下的rip寄存器的值
            except Exception as e:
                print(f"ERROR: {e}")
            else:
                mem_addr = cur_rip + offset  # 作用是相对寻址
                if(mem_addr in str_addrs):  # 找到了有关string的地址
                    # print(f'Look we have found a string: {mem_addr}')
                    op_str = op_str.replace(match.group(1), 'string')
                    # print(op_str)
        op_str = op_str.replace('[', '[ ')
        op_str = op_str.replace(']', ' ]')

    # xxxxxxh
    pattern = re.compile(r'.*([0-9a-fA-F]{6}h)')
    match = pattern.match(op_str)
    if(match):
        # print('match of symbol and address')
        content = match.group(1)
        symbol = project.loader.find_symbol(int(content[:-1], 16))
        if(symbol):
            op_str = op_str.replace(content, 'symbol')
        else:
            if('0ff' in op_str):  # 数足够大？abb0ff?
                pass
            else:
                op_str = op_str.replace(content, 'address')

    return op_str


def get_bb_seq(project, func):
    seq = []
    '''
    format should be like:结果
    ["mov rbp rdi", 
        "mov ebx 0x1", 
        "mov rdx rbx", 
        "call memcpy", 
        "mov [ rcx + rbx ] 0x0", 
        "mov rcx rax", 
        "mov [ rax ] 0x2e"]
    '''
    for block in func.blocks:
        bseq = []
        b = block.disassembly
        for ins in b.insns:
            temp_ins = []
            temp_ins.append(ins.mnemonic)
            temp_ins.append(handle_op(project, ins.op_str, ins.address, func))  # 替换string address symbol
            bseq.append(' '.join(temp_ins))
        seq.append((block.addr, bseq))
    return seq  # [(addr1,block_of_inst1).....]

def get_node_dict(graph):  # 创建node address 对应字典，应该是在func层调用的
    res = {}
    for node in graph.nodes():
        res[node.addr] = node
    return res


def has_edge(graph, saddr, eaddr):
    for node in graph.nodes():
        if(node.addr == saddr):  # node
            return True if(eaddr in [b.addr for b in graph[node]]) else False
    print(f"saddr {saddr not in graph}")
    return False


def get_structural_embedding(func, ndict):  ## 分析作用画：出邻接图
    graph = func.transition_graph

    block_addr =[b.addr for b in func.blocks]
    adjacency = pd.DataFrame(np.eye(len(block_addr), dtype=np.int32), index=block_addr, columns=block_addr)
    # self : 1, distant but joined: 1/min_distance, not joined: 0
    for col in range(len(block_addr)):
        for row in range(len(block_addr)):
            if(row==col):
                continue
            saddr = adjacency.columns[col]
            eaddr = adjacency.index[row]

            if(saddr not in ndict):
                continue

            if(has_edge(graph, saddr, eaddr)):
                adjacency.iloc[row, col] = 1

    return adjacency


def process_file(project, addr, cfg, ndict):  # ndict
    seq, adjacency = [], []
    try:
        func = cfg.kb.functions[addr]
        seq = get_bb_seq(project, func) ## 规范化每个instruction，List内包string形式，不知道为啥没用上
        # if(adj):
        # print("process file func")
        # print(func)
        adjacency = get_structural_embedding(func, ndict)

    except Exception as e:
        print(f'ERROR: {e}')

    return seq, adjacency


def process_data(entries_with_folders):
    # global project, previous_b, testData, folders, base_addr, testData
    # print("This is testData")
    # print(testData)
    palmtree = utils.UsableTransformer(model_path="./palmtree/pretrained_palmtree", vocab_path="./palmtree/vocab")
    bin_name, folders = entries_with_folders
    bpath = os.path.join(folders['bin'], bin_name)
    lab_new, emb_new, adj_new = {}, {}, {}
    bpath = os.path.join(folders['bin'], bin_name)  # data 在外围为bins 是二进制文件路径集合
    # print(bpath)
    project = angr.Project(bpath, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast()
    ndict = get_node_dict(cfg)
    # print("node dict")
    # print(ndict)
    # adj = True if not os.path.exists(os.path.join(folders['adj'],  data.replace('/','@@')+".pkl")) else False
# 此处的addr涉及到了想要分析的特定的fuc地址？
    for func_addr in cfg.kb.functions:  # 这里的vaddr获得的依据·是什么
        func = cfg.kb.functions[func_addr]
        labels, adjacency = process_file(project, func_addr, cfg, ndict) #返回一个function的sequence和邻接图
        adj_new[(bin_name, func_addr, func.name)] = adjacency
        # print(f"labels:{labels}")
        assert (bin_name, func_addr, func.name) not in emb_new
        emb_new[(bin_name, func_addr, func.name)] = []
        for baddr, instrs in labels:  # [(addr1,block_of_inst1).....]
            # print(len(instrs))
            if not instrs:
                continue
            temb = palmtree.encode(instrs)
            ins_shape = temb.shape
            # print(type(ins_shape), ins_shape[0], len(instrs))
            assert (ins_shape[0] == len(instrs))
            emb_new[(bin_name, func_addr, func.name)].append((baddr, temb))
        # print(f"!!!!!!{emb_new}")
    # with open(os.path.join(folders['emb'],  data.replace('/','@@')+".pkl"),"wb") as f:
        # pickle.dump(lab_new, f)
    # if(adj):
    print("开始输出")
    with open(os.path.join(folders['adj'],  bin_name+".pkl"),"wb") as f:
        pickle.dump(adj_new, f)
    with open(os.path.join(folders['emb'],  bin_name+".pkl"),"wb") as f:
        pickle.dump(adj_new, f)
    return lab_new, adj_new


if __name__ == '__main__':
    folders = {
        'home': './data',
        'bin': os.path.join('./data', "bin/"),
        'emb': os.path.join('./data', "emb/"),
        'adj': os.path.join('./data', "adj/")
    }

    directory = folders['bin']
    all_entries = os.listdir(directory)
    entries_with_folders = [(entry, folders) for entry in all_entries]

    num_processes = 8
    multiprocessing.set_start_method('spawn')
    with multiprocessing.Pool(processes=num_processes) as pool:
        results = pool.map(process_data, entries_with_folders)
