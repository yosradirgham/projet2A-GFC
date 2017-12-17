# -*- coding: utf-8 -*-

import re


class Method:

    def __init__(self, return_type, name, arg_types):
        self.return_type = return_type
        self.name = name
        self.arg_types = arg_types

    def __eq__(self, other):
        return (self.return_type == other.return_type
                and self.name == other.name
                and self.arg_types == other.arg_types)

    def __str__(self):
        return "%s %s ( %s )" % (self.return_type, self.name, ", ".join(self.arg_types))

    @classmethod
    def declaration_to_method(cls, string):
        words = re.split('\W+', string)
        if words[1] == "instance":
            words.pop(1)
        return_type = words[2]
        name = words[3]
        arg_types = []
        for i in range(4, len(words) - 4, 2):
            arg_types.append(words[i])
        return cls(return_type, name, arg_types)

    @classmethod
    def label_to_method(cls, label):
        if label[1] == "instance":
            label.pop(1)    # Enlever le 'instance'
        return_type = label[1]
        name = label[4]
        arg_types = []
        for i in range(5, len(label) - 1):
            arg_types.append(label[i])
        return cls(return_type, name, arg_types)
