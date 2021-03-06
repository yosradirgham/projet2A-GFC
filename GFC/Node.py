# -*- coding: utf-8 -*-

import NodeID
import re

# Un noeud du graphe contient un identifiant (ID), un label (le nom de l'instruction et les arguments stockés dans une
# liste), et la liste de ses successeurs (qui sont eux-mêmes des noeuds)


class Node:

    # Construit un noeud à partir d'une ligne de CIL de la forme "IL_0001  ldc.i4".
    # Il faut aussi passer en argument le numéro de la méthode correspondante pour construire correctement l'ID.
    def __init__(self, cil_line, method):
        index = int(cil_line[3:7], 16)  # On extrait le num de ligne écrit en base 16
        self.ID = NodeID.NodeID(method, index)   # On construit l'ID avec la méthode et l'index relatif
        self.label = re.split('\W+', cil_line)[1:]   # On extrait le nom de l'instruction et les arguments
        self.succs = []

    def __hash__(self):
        return hash((str(self.ID))) #, self.label))

    # Deux noeuds sont égaux ssi ils ont le même identifiant.
    def __eq__(self, other):
        return self.ID == other.ID

    def get_method(self):
        return self.ID.get_method()

    def get_label(self):
        return self.label

    def get_instruction(self):
        if ('tail.' in self.label[0] or 'unaligned.' in self.label[0] or 'no.' in self.label[0]
            or 'volatile.' in self.label[0] or 'constrained.' in self.label[0] or 'readonly.' in self.label[0]):
            return self.label[1]
        else:
            return self.label[0]

    def get_ID(self):
        return self.ID

    def add_succs(self, other):
        self.succs.append(other)
