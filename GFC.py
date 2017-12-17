# -*- coding: utf-8 -*-

import Node
import NodeID
import Method
import struct


def instr_type(data):
    opcode = data[0]
    # Cas préfixe
    if ('tail.' in opcode or 'unaligned.' in opcode or 'no.' in opcode or 'volatile.' in opcode
            or 'constrained.' in opcode or 'readonly.' in opcode):
        opcode = data[1]
    # Cas 1 : return
    if 'ret' in opcode or 'endfault' in opcode or 'endfinally' in opcode or 'leave' in opcode:
        return 1
    # Cas 2 : appel fonction
    elif ('call' in opcode or 'newobj' in opcode or 'jmp' in opcode) and ('localloc' not in opcode):
        return 2
    # Cas 3 : saut inconditionnel
    elif opcode == 'br' or opcode == 'br.s':
        return 3
    # Cas 4 : exception
    # Les instructions qui lèvent de façon conditionnelle les exceptions sont-elles à prendre en compte ?
    # Ex : opcode 0x82 à 0x8b et les autres instructions de conversion
    elif 'throw' in opcode or 'break' in opcode or 'conv.ovf' in opcode or 'ckfinite' in opcode:
        return 4
    # Cas 5 : appel à une fonction d'une librairie inaccessible
    elif 'EXT' in opcode:
        return 5
    # Cas 8 : saut conditionnel
    elif ('br' in opcode or 'beq' in opcode or 'bge' in opcode or 'ble' in opcode or 'bgt' in opcode or 'blt' in opcode
          or 'bne' in opcode):
        return 8
    # Cas 12 : switch
    elif 'switch' in opcode:
        return 12
    else:
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
            if line[:7] == ".method":  # Si on rencontre une nouvelle méthode, on enregistre le nom qui se trouve
                method = Method.Method.declaration_to_method(file.readline())  # dans la ligne suivante
                self.methods.append(method)
            if line[:2] == "IL":  # Si la ligne contient une instruction, on la stocke dans un noeud
                self.add_node(Node.Node(line, method))

        # Construisons maintenant la liste des successeurs de chaque noeud
        for i in range(len(self.nodes)):

            if instr_type(self.nodes[i].get_label()) != 1 and 'throw' not in self.nodes[i].get_instruction():
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
                else:
                    self.nodes[i].label[0] += " EXT"

                    # Reste à traiter l'instruction jmp

    def add_node(self, node):
        self.nodes.append(node)

    # Prend un ID et retourne le noeud de nodes_list correspondant.
    def find_node(self, ID):
        for node in self.nodes:
            if ID == node.get_ID():
                return node
        return None

    def to_dot(self, filename):
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

    def instr_type_to_dot(self, filename):
        fichier = open(filename, "w")
        fichier.write("digraph GFC {\n")
        for node in self.nodes:
            fichier.write('"%s%s"[label="%s"];\n' %
                          (node.ID.get_method(), node.ID.get_index(), str(instr_type(node.label))))
            for i in range(len(node.succs)):
                fichier.write('"%s%s" -> "%s%s"[label="%s"];\n' %
                              (node.ID.get_method(), node.ID.get_index(),
                               node.succs[i].ID.get_method(), node.succs[i].ID.get_index(), i))
        fichier.write("}\n")

    def to_edg(self, filename):
        fichier = open(filename, "wb")
        fichier.write(bytes("GRAPHBIN", encoding="ascii"))
        fichier.write(struct.pack("I", len(self.nodes)))
        cpt = 1
        index = dict()
        for node in self.nodes:
            fichier.write(bytes("n", encoding="ascii"))
            fichier.write(struct.pack('Q', cpt))
            fichier.write(struct.pack('I', instr_type(node.label)))
            index[node] = cpt
            cpt = cpt + 1
        for node in self.nodes:
            for elt in node.succs:
                fichier.write(bytes("e", encoding="ascii"))
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
g.to_dot("test.dot")
g.instr_type_to_dot("graphe_types.dot")
# g.to_edg("graphe.edg")
