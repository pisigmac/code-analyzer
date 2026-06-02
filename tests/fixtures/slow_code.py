"""Test fixture with performance issues."""


def inefficient_loop():
    result = []
    for i in range(100):
        result.append(i * 2)
    return result


def string_concatenation():
    result = ""
    for i in range(100):
        result += str(i)
    return result


def unnecessary_list():
    data = list()
    return data


def import_in_function():
    import json
    return json.dumps({"key": "value"})


def repeated_dict_lookup():
    data = {"key": "value"}
    for i in range(100):
        print(data["key"])
        print(data["key"])
        print(data["key"])


def range_len_loop(items):
    for i in range(len(items)):
        print(items[i])


def membership_in_list(x):
    return x in [1, 2, 3, 4, 5]


def dict_keys_iteration(d):
    for k in d.keys():
        print(k)


def mutable_default(items=[]):
    items.append(1)
    return items


def sorted_for_min(numbers):
    return sorted(numbers)[0]


def open_without_with(path):
    f = open(path)
    data = f.read()
    f.close()
    return data


def open_without_encoding(path):
    with open(path) as f:
        return f.read()
