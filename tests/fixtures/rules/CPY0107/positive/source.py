from functools import reduce

total = reduce(function=lambda left, right: left + right, sequence=[1, 2])
