

# from re import ASCII
import binascii
from netzob.all import *
import graphviz

#（一）导入并读取pcap文件

messages_session1 = PCAPImporter.readFile("../pcap/target_src_v1_session1.pcap").values()
messages_session2 = PCAPImporter.readFile("../pcap/target_src_v1_session2.pcap").values()
messages = messages_session1 + messages_session2

symbol = Symbol(messages = messages)
#print(symbol.str_data())
with open('./out/messages_0.txt', 'w') as f:
    f.write(symbol.str_data())


# （二）消息格式推断

# (1)使用分隔符做格式区分
Format.splitDelimiter(symbol, String("#"))
# print(symbol.str_data()) #普通打印
with open('./out/messages_1_1splitDelimiter.txt', 'w') as f:
    f.write(symbol.str_data())
with open('./out/messages_1_2splitDelimiter.txt', 'w') as f:
    f.write(symbol.str_structure())
# print(symbol.str_structure()) #结构化处理后的打印

# (2)根据关键字段分簇,用这个函数对处理过的symbol进行分簇，并将分簇的结果打印出来
symbols = Format.clusterByKeyField(symbol,symbol.fields[0])

print('[+] Number of symbols after clustering:{0}'.format(len(symbols)))
# print('[+] Symbol list:')
with open('./out/messages_2_clusterByKeyfiled.txt', 'w') as f:
    f.truncate(0)
for keyFieldName,s in symbols.items():#分簇算法生成了14个不同的symbol，每个symbol都由一个唯一的第一个字段
    with open('./out/messages_2_clusterByKeyfiled.txt', 'a') as f:
        f.write('* {0}'.format(keyFieldName))
        f.write('\n')
#     print('* {0}'.format(keyFieldName))

# (3)在每个symbol中以序列对齐来区分格式
# 重组消息，并且将每个消息分解成三个基本字段：命令字段、分割字段（在这个报文消息中就是“#”）、不定长内容。
# 这里重点关注不定长内容字段，具有动态大小的字段是我们在使用Netzob中将序列对齐的良好选择。这样就能很清晰地判断出来是这个子字段大小是可变还是不可变的。为了做到这个，使用splitAligned()函数
with open('./out/messages_3_splitAligned.txt', 'w') as f:
    f.truncate(0)
for symbol in symbols.values():
    Format.splitAligned(symbol.fields[2],doInternalSlick=True)#将symbol中的第三个（0、1、2所以是第三个）域作为对齐的依据，进行对齐
    with open('./out/messages_3_splitAligned.txt', 'a') as f:
        f.write(symbol.str_data())
        f.write('\n')
    # print('[+] Partitionned messages:')
    # print(symbol.str_data())

# (4)找到每个symbol的关系
# 现在我们想看到每个消息之间的关系。Netzob的API提供了能够确定潜在关系的函数RelationFinder.findOnSymbol()
with open('./out/messages_4_findOnSymbol.txt', 'w') as f:
    f.truncate(0)
for symbol in symbols.values():
    rels = RelationFinder.findOnSymbol(symbol)
    with open('./out/messages_4_findOnSymbol.txt', 'a') as f:
        f.write("[+] Relations found: \n")
        for rel in rels:
            f.write("  " + rel["relation_type"] + ", between '" + rel["x_attribute"] + "' of:\n")
            f.write("    " + str('-'.join([f.name for f in rel["x_fields"]]))+'\n')
            p = [v.getValues()[:] for v in rel["x_fields"]]
            f.write("    " + str(p)+'\n')
            f.write("  " + "and '" + rel["y_attribute"] + "' of:"+'\n')
            f.write("    " + str('-'.join([f.name for f in rel["y_fields"]]))+'\n')
            p = [v.getValues()[:] for v in rel["y_fields"]]
            f.write("    " + str(p)+'\n')
        

    # print("[+] Relations found: ")
    # for rel in rels:
    #     print("  " + rel["relation_type"] + ", between '" + rel["x_attribute"] + "' of:")
    #     print("    " + str('-'.join([f.name for f in rel["x_fields"]])))
    #     p = [v.getValues()[:] for v in rel["x_fields"]]
    #     print("    " + str(p))
    #     print("  " + "and '" + rel["y_attribute"] + "' of:")
    #     print("    " + str('-'.join([f.name for f in rel["y_fields"]])))
    #     p = [v.getValues()[:] for v in rel["y_fields"]]
    #     print("    " + str(p))

# (5)应用找到的symbol结构之间的关系
#  可以修改消息格式来应用找到的关系。通过创建一个Size字段来做这个，这个字段的值依赖目标字段的内容。
with open('./out/messages_5_ModifyFormatByRels.txt', 'w') as f:
    f.truncate(0)
for symbol in symbols.values():
    rels = RelationFinder.findOnSymbol(symbol)

    for rel in rels:

        # Apply first found relationship
        rel = rels[0]
        rel["x_fields"][0].domain = Size(rel["y_fields"])#, factor=1/8/0
    with open('./out/messages_5_ModifyFormatByRels.txt', 'a') as f:
        f.write("[+] Symbol structure:\n")
        f.write(symbol.str_structure()+'\n')
    # print("[+] Symbol structure:")
    # print(symbol.str_structure())

# （三）状态机推断
# 协议可以使用无限状态机来进行描述，使用Netzob工具对官方提供的抓包pcap例子进行状态机的推断。

#利用消息格式推断得到的symbol信息抽象状态机

#  (1)生成一个状态机链
# 创建一个message session
session = Session(messages_session1)

# 根据推断的symbols，抽象session
abstractSession = session.abstract(list(symbols.values()))

# 生成automata，根据观测到的messages/symbols序列
automata = Automata.generateChainedStatesAutomata(abstractSession, list(symbols.values())) 

# #使用generateDotCode()函数创建dotcode以便更好观察状态机
dotcode = automata.generateDotCode() 
with open('./out/dot/automata_1_chain.dot', 'w') as f:
    f.write(dotcode)
# 使用Graphviz将dotcode转换为可视化状态机
graph = graphviz.Source(dotcode)
graph.render('./out/dot/automata_1_chain', format='png', view=True)
# print(dotcode)

# （2）生成一个单一状态机
# Create a session of messages
session = Session(messages_session1)

# Abstract this session according to the inferred symbols
abstractSession = session.abstract(list(symbols.values()))

# Generate an automata according to the observed sequence of messages/symbols
automata = Automata.generateOneStateAutomata(abstractSession, list(symbols.values()))

# Print the dot representation of the automata
dotcode = automata.generateDotCode()
with open('./out/dot/automata_2_OneState.dot', 'w') as f:
    f.write(dotcode)
# 使用Graphviz将dotcode转换为可视化状态机
graph = graphviz.Source(dotcode)
graph.render('./out/dot/automata_2_OneState', format='png', view=True)

# print(dotcode)

# #（3）生成一个基于PTA的状态机
# 将从不同PCAP文件中获取的多个消息序列转换为一个自动机，
# 然后合并相同的路径。底层的合并策略称为前缀树自动机接受器
messages_session1 = PCAPImporter.readFile("../pcap/target_src_v1_session1.pcap").values()
messages_session3 = PCAPImporter.readFile("../pcap/target_src_v1_session3.pcap").values()

session1 = Session(messages_session1)
session3 = Session(messages_session3)

abstractSession1 = session1.abstract(list(symbols.values()))
abstractSession3 = session3.abstract(list(symbols.values()))
#???
automata = Automata.generatePTAAutomata([abstractSession1, abstractSession3], list(symbols.values()))

dotcode = automata.generateDotCode()
with open('./out/dot/automata_3_PTA.dot', 'w') as f:
    f.write(dotcode)

graph = graphviz.Source(dotcode)
graph.render('./out/dot/automata_3_PTA', format='png', view=True)

# print(dotcode)

# # 将dotcode保存到文件中
# with open('my_automata.dot', 'w') as f:
#     f.write(dotcode)
# # 使用Graphviz将dotcode转换为可视化状态机
# graph = graphviz.Source(dotcode)
# graph.render('my_automata', format='png', view=True)