# -*- coding: utf-8 -*-

import Node
import NodeID
import Method
import struct


def instr_type(data):
    opcode = data[0]
    if 'call' in opcode:
        return 2
    elif 'br' in opcode:
        return 8
    elif 'ret' in opcode:
        return 1
    elif 'throw' in opcode:
        return 5
    elif 'newobj' in opcode:
        return 2
    else:
        print(opcode)
        return 9


# Un graphe est tout simplement une liste de noeuds.
class GFC:

    # Un constructeur pour construire un GFC à partir d'un fichier texte de CIL
    def __init__(self, file_name):

        # Construisons dans un premier temps la liste de noeuds sans s'intéresser aux successeurs
        self.nodes = []
        self.methods = []

        file = open(file_name, "r")

        line = "\n"
        while line != "":
            line = unindent(file.readline())
            if line[:7] == ".method":     # Si on rencontre une nouvelle méthode, on enregistre le nom qui se trouve
                method = Method.Method.declaration_to_method(file.readline())  # dans la ligne suivante
                self.methods.append(method)
            if line[:2] == "IL":   # Si la ligne contient une instruction, on la stocke dans un noeud
                self.add_node(Node.Node(line, method))

        # Construisons maintenant la liste des successeurs de chaque noeud
        for i in range(len(self.nodes)):

            if self.nodes[i].get_instruction() != "ret" and self.nodes[i].get_instruction() != "throw":
                self.nodes[i].add_succs(self.nodes[i + 1])

            temp = find_IL(self.nodes[i].get_label())
            if temp is not None:
                self.nodes[i].add_succs(self.find_node(NodeID.NodeID(self.nodes[i].get_method(), temp)))

            if (self.nodes[i].get_instruction() == "call"
                or self.nodes[i].get_instruction() == "callvirt"
                or self.nodes[i].get_instruction() == "newobj"):
                called_method = Method.Method.label_to_method(self.nodes[i].get_label())
                suc = self.find_node(NodeID.NodeID(called_method, 0))
                if suc is not None:
                    self.nodes[i].add_succs(suc)

            # Reste à traiter l'instruction jmp

    def add_node(self, node):
        self.nodes.append(node)

    # Prend un ID et retourne le noeud de nodes_list correspondant.
    def find_node(self, ID):
        for node in self.nodes:
            if ID == node.get_ID():
                return node
        return None

    def export(self, filename):
        fichier = open(filename, "w")
        fichier.write("digraph GFC {\n")
        for node in self.nodes:
            fichier.write('"%s%s"[label="%s"];\n' %
                          (node.ID.get_method(), node.ID.get_index(), node.label[0]))
            for i in range(len(node.succs)):
                fichier.write('"%s%s" -> "%s%s"[label="%s"];\n' %
                              (node.ID.get_method(), node.ID.get_index(),
                               node.succs[i].ID.get_method(), node.succs[i].ID.get_index(), i))
        fichier.write("}\n")

    def to_edg(self, filename):
        fichier = open(filename, "wb")
        fichier.write("GRAPHBIN")
        fichier.write(struct.pack("I", len(self.nodes)))
        cpt = 1
        index = dict()
        for node in self.nodes:
            fichier.write("n")
            fichier.write(struct.pack('Q', cpt))
            fichier.write(struct.pack('I', instr_type(node.label)))
            index[node] = cpt
            cpt = cpt + 1
        for node in self.nodes:
            for elt in node.succs:
                fichier.write("e")
                fichier.write(struct.pack('Q', index[node]))
                fichier.write(struct.pack('Q', index[elt]))
        

def unindent(my_string):
    if my_string != "":
        while my_string[0] == ' ' or my_string[0] == '\t':
            my_string = my_string[1:]
    return my_string


def find_IL(label):
    for word in label:
        if word[:2] == "IL":
            return int(word[3:7], 16)
    return None


g = GFC("test.cil")
print(g)
g.export("graphe.dot")
# g.to_edg("graphe.edg")



