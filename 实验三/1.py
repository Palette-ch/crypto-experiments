import math

p, q = 1009, 3643
phi = (p-1)*(q-1)
lam = (p-1)*(q-1) // math.gcd(p-1, q-1)   # lcm

def fixed_points_count(e):
    a = math.gcd(e-1, p-1) + 1
    b = math.gcd(e-1, q-1) + 1
    return a * b

min_cnt = float('inf')
best_e_sum = 0

for e in range(2, phi):
    if math.gcd(e, phi) != 1:
        continue
    cnt = fixed_points_count(e)
    if cnt < min_cnt:
        min_cnt = cnt
        best_e_sum = e
    elif cnt == min_cnt:
        best_e_sum += e

print("最小不动点数量:", min_cnt)
print("符合条件的 e 之和:", best_e_sum)