from functools import reduce

total = reduce(lambda left, right: left + right, [1, 2])
