# -*- coding: utf-8 -*-

import Node


# Un graphe est tout simplement une liste de noeuds.
class GFC:

    # Un constructeur pour construire un GFC à partir d'un fichier texte de CIL
    def __init__(self, file_name):

        # Construisons dans un premier temps la liste de noeuds sans s'intéresser aux successeurs
        self.nodes = []

        file = open(file_name, "r")

        line = "\n"
        while line != "":
            line = unindent(file.readline())
            if line[:7] == ".method":     # Si on rencontre une nouvelle méthode, on enregistre le nom qui se trouve
                method = file.readline()  # dans la ligne suivante
            if line[:2] == "IL":   # Si la ligne contient une instruction, on la stocke dans un noeud
                self.add_node(Node.Node(line, method))

        # Construisons maintenant la liste des successeurs de chaque noeud
        for i in range(len(self.nodes)):

            if self.nodes[i].getInstruction != "ret" and self.nodes[i].getInstruction != "throw":
                self.nodes[i].addSuccs()

    def add_node(self, node):
        self.nodes.append(node)

    def __str__(self):
        to_print = []
        for node in self.nodes:
            to_print.append(str(node.ID.getMethod()) + ' ' + str(node.ID.getIndex()) + ' ' + node.label)
        return '\n'.join(to_print)


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



