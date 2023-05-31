def dotprod [n] (xs: [n]f64) (ys: [n]f64): f64 =
    (reduce (+) (0f64) (map2 (*) xs ys))

def matmul [n][p][m] (xss: [n][p]f64) (yss: [p][m]f64): *[n][m]f64 =
    map (\xs -> map (dotprod xs) (transpose yss)) xss

--
-- ==
-- entry: matmul_bench
-- compiled random input {[5000][10]f64 [10][5000]f64}
-- compiled random input {[10][5000]f64 [5000][10]f64}

entry matmul_bench [n][p][m] (xss: [n][p]f64) (yss: [p][m]f64) =
    matmul xss yss