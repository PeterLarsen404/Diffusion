import "./cnn"
import "../gen_random/mk_random"
import "../lenet/lenet"
import "../utils/lossfun"
import "../utils/optimizers"


let main (x_train : [][][]f64) (y_train : [][]f64) =
  let some_x_train = x_train[:10]
  let some_y_train = y_train[:10]
  let some_x_test = x_train[10]
  let some_y_test = y_train[10]

  let seeds = mk_rand_seeds 42 5
  let weights = mk_lenet_wandb seeds

  let (trained_weights,losses) = train_lenet some_x_train some_y_train 200 weights
  let (trained_weights_ad,losses2) = train_lenet some_x_train some_y_train 700 weights

  let truth = loop (truth_arr) = ([]) for i < 99 do
    let (pred,_) = lenet_forward some_x_test[i] new_weights
    let max = foldr

  --in generated_3_2
  --let (pred,_) = lenet_forward x_train[300] new_weights
  --in (pred,y_train[300])