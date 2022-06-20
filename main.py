# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import hashlib
import math
import base64
import socket


def add_node(list,leaf):

    list.append(hashlib.sha256(str(leaf).encode('utf-8')).hexdigest())


def find_root(list, first, end):
    if len(list) == 0:
        return
    if first == end:
        return list[first]
    x = math.floor(math.log((end-first+1), 2))
    if math.pow(2, x) == end-first+1:
        x = x - 1
    left = find_root(list, first,int(first + math.pow(2, x)-1))
    right = find_root(list,int( first + math.pow(2, x)) , end)
    return hashlib.sha256(str(left + right).encode('utf-8')).hexdigest()

def find_proof(list, i, j, index, result_list):
    if i == j:
        result_list.append(list[index])
        return
    x = math.floor(math.log((j - i + 1), 2))
    if math.pow(2, x) == j - i + 1:
        x = x - 1
    if i <= index <= math.pow(2, x)+i-1:
        find_proof(list, i, int(math.pow(2, x)+i-1), index, result_list)
        result_list.append(find_root(list, int(math.pow(2, x)+i), j))
    else:
        find_proof(list,int(math.pow(2, x) + i), j, index, result_list)
        result_list.append(find_root(list, i, int(math.pow(2, x)+i-1)))

def print_the_proof(res_list_proof):
    print_list=" ".join(str(x) for x in res_list_proof)
    print(print_list)

def proof_of_inclusion(leaf,root,proof):

    tmp = hashlib.sha256(str(leaf).encode('utf-8')).hexdigest()
    for x in proof:
        tmp = hashlib.sha256(str(tmp+x).encode('utf-8')).hexdigest()

    print(root == tmp)



if __name__ == '__main__':
    list = []

    while True:
        res_list_proof = []
        parameter = input()
        action_value = parameter.split()
        choose = action_value[0]

        if choose == '1':
            add_node(list, action_value[1])
        elif choose == '2':
            print(find_root(list, 0, len(list)-1))
        elif choose == '3':
            res_list_proof.append(find_root(list, 0, len(list)-1))
            find_proof(list, 0, len(list)-1, int(action_value[1]), res_list_proof)
            print_the_proof(res_list_proof)
        elif choose == '4':
            proof_of_inclusion(action_value[1],action_value[2],action_value[3:])
        elif choose == 5:
            fun5()
        elif choose == 6:
            fun6()
        elif choose == 7:
            fun7()


