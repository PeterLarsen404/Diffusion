import "./cnn"
import "../gen_random/mk_random"
import "../lenet/lenet"
import "../utils/lossfun"


-- Test futhark-ad
-- ==
-- entry: test_cnn_futhark_ad
-- compiled input @ ../datasets/cnn/mnist_1000.in
-- output {[[[-0.197280f64, 0.139221f64, 0.084688f64, -0.052453f64, -0.055049f64], [0.055111f64, -0.170110f64, -0.141256f64, 0.133998f64, 0.188985f64], [-0.182143f64, -0.100486f64, -0.035410f64, 0.169786f64, 0.021356f64], [-0.179429f64, -0.078519f64, 0.060122f64, 0.035273f64, -0.147171f64], [-0.193348f64, 0.003432f64, 0.082803f64, 0.048082f64, -0.110512f64]]]}

-- Benchmark cnn
-- ==
-- entry: bench_cnn
-- compiled random input {[1][28][28]f64 [1][10]f64 1i64}
-- compiled random input {[1][28][28]f64 [1][10]f64 10i64}

-- Benchmark futhark-ad
--
-- entry: bench_cnn_futhark_ad
-- compiled random input {[1][28][28]f64 [1][10]f64 1i64}
-- compiled random input {[1][28][28]f64 [1][10]f64 10i64}

let seeds = mk_rand_seeds 42 5
let weights = mk_lenet_wandb seeds

entry test_cnn_futhark_ad [l][m][n] (x_train : [l][m][n]f64) (y_train : [l][10]f64) =
  let (trained_weights,losses) = train_lenet_ad x_train[:100] y_train[:100] 1 (copy weights)
  in (trained_weights.0)[0]

entry bench_cnn [l][m][n] (x_train : [l][m][n]f64) (y_train : [l][10]f64) (epochs : i64) =
  let (trained_weights,losses) = train_lenet x_train[:100] y_train[:100] epochs (copy weights)
  in losses

entry bench_cnn_futhark_ad [l][m][n] (x_train : [l][m][n]f64) (y_train : [l][10]f64) (epochs : i64)=
  let loss weights = mse y_train[0] (lenet_forward x_train[0] (copy weights)).0
  let grad_w = vjp loss (copy weights) 1f64
  in grad_w
