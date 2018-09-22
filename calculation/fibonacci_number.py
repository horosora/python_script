def fibonacci(n):
    a = 0
    b = 1
    for _ in range(n):
        tmp = a
        a = b
        b = b+tmp
    return a

print(fibonacci(10))

# 0 1 2 3 4 5 6 7  8  9  10
# 0 1 1 2 3 5 8 13 21 34 55