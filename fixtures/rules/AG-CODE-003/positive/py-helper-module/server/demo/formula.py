def evaluate(text: str) -> object:
    return eval(text, {"__builtins__": {}})
