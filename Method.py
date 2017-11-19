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
        string = self.return_type + " " + self.name + "("
        for arg in self.arg_types:
            string += arg + ", "
        string = string[:-2]
        string += ")"
        return string

    @classmethod
    def declaration_to_method(cls, string):
        words = re.split('\W+', string)
        if words[0] == "instance":
            words.pop(0)
        return_type = words[1]
        name = words[2]
        arg_types = []
        for i in range(3, len(words) - 4, 2):
            arg_types.append(words[i])
        return cls(return_type, name, arg_types)


