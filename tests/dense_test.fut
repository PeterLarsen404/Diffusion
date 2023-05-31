import "../layers/dense"

-- test dense forward
-- ==
-- entry: dense_test
-- compiled input @ ../datasets/dense/test_2_4.in
-- output @ ../datasets/dense/test_2_4.out

-- test dense forward
-- ==
-- entry: dense_test
-- compiled input @ ../datasets/dense/test_8_4.in
-- output @ ../datasets/dense/test_8_4.out


-- test dense backward
-- ==
-- entry: dense_test_b
-- compiled input @ ../datasets/dense/test_2_4_b.in
-- output @ ../datasets/dense/test_2_4_b.out

-- test dense backward
-- ==
-- entry: dense_test_b
-- compiled input @ ../datasets/dense/test_8_4_b.in
-- output @ ../datasets/dense/test_8_4_b.out

-- bench dense forward
-- ==
-- entry: dense_test
-- compiled random input {[256]f64 [64][256]f64 [64]f64}
-- compiled random input {[256]f64 [256][256]f64 [256]f64}
-- compiled random input {[1000]f64 [5000][1000]f64 [5000]f64}


-- bench dense backward
-- ==
-- entry: dense_test_b
-- compiled random input {[64]f64 [256]f64 [64][256]f64}
-- compiled random input {[256]f64 [256]f64 [256][256]f64}
-- compiled random input {[5000]f64 [1000]f64 [5000][1000]f64}



entry dense_test [m][n] (img : [n]f64) (img_w : [m][n]f64) (img_b : [m]f64) =
  dense img img_w img_b

entry dense_test_b [m][n] (grad : [m]f64) (img : [n]f64)  (img_w : [m][n]f64) =
  dense_b grad img img_w