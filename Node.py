# -*- coding: utf-8 -*-

import NodeID

# Un noeud du graphe contient un identifiant (ID), un label (le nom de l'instruction et les arguments stockés dans une
# liste), et la liste de ses successeurs (qui sont eux-mêmes des noeuds)


class Node:

    # Construit un noeud à partir d'une ligne de CIL de la forme "IL_0001  ldc.i4".
    # Il faut aussi passer en argument le numéro de la méthode correspondante pour construire correctement l'ID.
    def __init__(self, cil_line, method):
        index = int(cil_line[3:7], 16)  # On extrait le num de ligne écrit en base 16
        self.ID = NodeID.NodeID(method, index)   # On construit l'ID avec l'index et le numéro de la méthode
        self.label = cil_line[10:-1].split(' ')   # On extrait le nom de l'instruction et les arguments
        self.succs = []

    # Deux noeuds sont égaux ssi ils ont le même identifiant.
    def __eq__(self, other):
        return self.ID == other.ID

    def get_method(self):
        return self.ID.get_method()

    def get_label(self):
        return self.label

    def get_instruction(self):
        return self.label[0]

    def get_ID(self):
        return self.ID

    def add_succs(self, other):
        self.succs.append(other)
