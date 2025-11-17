n = 0
min = 1000000
max = 0
total = 0
while True:
    s = input()
    try:
        f = s[10:s.rfind('µ')]
    except:
        continue
    try:
        t = float(f)
    except:
        continue
    if t < min:
        min = t
    if t > max:
        max = t
    total += t
    n += 1
    print(f'avg={(total / n):.3f}µs - min={min:.3f} - max={max:.3f}')
