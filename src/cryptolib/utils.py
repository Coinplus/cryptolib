
def count_leading_values(lst, c):
    n = 0
    l = len(lst)
    while n < l and lst[n] == c:
        n += 1
    return n


