# -*- coding: utf-8 -*-

import Node

# Un graphe est tout simplement une liste de noeuds.
class GFC:

    # Un constructeur pour construire un GFC à partir d'un fichier texte de CIL
    def __init__(self, file_name):

        self.nodes = []
        self._method_counter = -1  #Un compteur qui va nous servir à compter les méthodes dans un fichier de CIL
                                   # afin de pouvoir construire l'ID des différents noeuds
        file = open(file_name, "r")

        line = "\n"
        while line != "":
            line = unindent(file.readline())  #On lit une ligne et on vire les tabulations présentes en début de ligne
            if line[:7] == ".method":   #Si on rencontre ue nouvelle méthode, on incrémente le compteur
                self._method_counter += 1
            if line[:2] == "IL":   #Si la ligne contient une instruction, on la stocke dans un noeud
                self.add_node(Node.Node(line, self._method_counter))



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



