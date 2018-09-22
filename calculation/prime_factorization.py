def prime_factors(n):
    factors = []
    d = 2
    while n > 1:
        while n % d == 0:
            factors.append(d)
            n = n / d
        d = d + 1
        if d * d > n:
            if n > 1:
                factors.append(n)
            break
    return factors


print(prime_factors(300))   # [2, 2, 3, 5, 5]