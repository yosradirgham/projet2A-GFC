# -*- coding: utf-8 -*-

# Une classe pour décrire l'identifiant d'un noeud.
# Pour l'instant, un identifiant contient le nom de la méthode (la ligne venant juste après le .method), et le numéro
# de ligne relatif (l'index) (dans le bytecode, le num de ligne ressemble à IL_0001, IL00b4 etc.)

class NodeID:

    def __init__(self, method, index):
        self.method = method
        self.index = index

    def __eq__(self, other):
        return self.method == other.method and self.index == other.index

    def getMethod(self):
        return self.method

    def getIndex(self):
        return self.index
