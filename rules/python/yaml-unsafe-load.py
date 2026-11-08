import yaml


def parse(data):
    # ruleid: python.yaml-unsafe-load
    a = yaml.load(data)
    # ruleid: python.yaml-unsafe-load
    b = yaml.load(data, Loader=yaml.Loader)
    # ruleid: python.yaml-unsafe-load
    c = yaml.unsafe_load(data)
    # ok: python.yaml-unsafe-load
    d = yaml.safe_load(data)
    # ok: python.yaml-unsafe-load
    e = yaml.load(data, Loader=yaml.SafeLoader)
    return a, b, c, d, e
