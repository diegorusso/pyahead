import ast

node = ast.Name(id="x", ctx=ast.Load())


class Marker(ast.AST):
    """Subclassing an abstract node is not instantiating it."""
