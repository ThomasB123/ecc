def binary(num): # convert denary number to binary
    out = []
    while num > 0:
        if num % 2 == 1:
            num -= 1
            out.append(1)
        else:
            out.append(0)
        num /= 2
    return out

print(binary(151))