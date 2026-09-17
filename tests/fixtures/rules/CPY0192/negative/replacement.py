import ast

node = ast.Subscript(ast.Name("x", ast.Load()), ast.Constant(1), ast.Load())
tuple_node = ast.Tuple([ast.Slice()], ast.Load())
