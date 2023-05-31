import "../utils/actfun"

-- bench softmax forward
-- ==
-- entry: softmax_bench
-- compiled random input {[100]f64}
-- compiled random input {[1000]f64}
-- compiled random input {[10000]f64}

-- bench softmax forward
-- ==
-- entry: softmax_b_bench
-- compiled random input {[100]f64 [100]f64}
-- compiled random input {[1000]f64 [1000]f64}
-- compiled random input {[10000]f64 [10000]f64}
-- compiled random input {[100000]f64 [100000]f64}
-- compiled random input {[1000000]f64 [1000000]f64}


entry softmax_bench [n] (X : [n]f64) : [n]f64 =
  softmax X

entry softmax_b_bench [m] (out_grad : [m]f64) (softmax_pred : [m]f64) : [m][1]f64 =
  softmax_b out_grad softmax_pred