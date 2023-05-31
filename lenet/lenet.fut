import "../layers/conv2d"
import "../layers/avgpool"
import "../layers/dense"
import "../utils/actfun"
import "../utils/lossfun"


def lenet_forward [n][m] (img : [n][m]f64) (wandb) =
    let (C1_w,C1_b,C3_w,C3_b,F6_w,F6_b,F7_w,F7_b,F8_w,F8_b) = wandb
    let C1_layer : [6][28][28]f64 = convolve2D [img] C1_w C1_b 2 :> [6][28][28]f64
    let C1_layer_activation : [6][28][28]f64 = map (\ y -> map (\ x -> map ReLU x) y) C1_layer
    let S2_layer : [6][14][14]f64 = avg_pool C1_layer_activation 2 :> [6][14][14]f64
    let C3_layer : [16][10][10]f64 = convolve2D S2_layer C3_w C3_b 0 :> [16][10][10]f64
    let C3_layer_activation : [16][10][10]f64 = map (\ y -> map (\ x -> map ReLU x) y) C3_layer
    let S4_layer : [16][5][5]f64 = avg_pool C3_layer_activation 2 :> [16][5][5]f64
    let F5_layer : [400]f64 = flatten (flatten S4_layer) :> [400]f64
    let F6_layer : [120]f64 = dense F5_layer F6_w F6_b
    let F6_layer_activation : [120]f64 = map ReLU F6_layer
    let F7_layer : [84]f64 = dense F6_layer_activation F7_w F7_b
    let F7_layer_activation : [84]f64 = map ReLU F7_layer
    let F8_layer : [10]f64 = dense F7_layer_activation F8_w F8_b
    let prediction : [10]f64 = softmax F8_layer :> [10]f64
    in (prediction,(C1_layer,C1_layer_activation,S2_layer,C3_layer,C3_layer_activation,S4_layer,F5_layer,F6_layer,F6_layer_activation,F7_layer,F7_layer_activation,F8_layer))

def lenet_reverse [n][m] (img : [n][m]f64) (prediction : []f64) (label: []f64) (weights) (cache) =
  let (C1_w,C1_b,C3_w,C3_b,F6_w,F6_b,F7_w,F7_b,F8_w,F8_b) = weights
  let (C1_layer,C1_layer_activation,S2_layer,C3_layer,C3_layer_activation,S4_layer,F5_layer,F6_layer,F6_layer_activation,F7_layer,F7_layer_activation,F8_layer) = cache
  let grad = mse_prime label prediction
  let prediction_b : [10]f64 = softmax_b grad prediction :> [10]f64
  let (F8_layer_b,F8_w_grad,F8_b_grad) = dense_b prediction_b F7_layer_activation F8_w
  let F7_layer_activation_b : [84]f64 = map2 ReLU_b F8_layer_b F7_layer
  let (F7_layer_b,F7_w_grad,F7_b_grad) = dense_b F7_layer_activation_b F6_layer F7_w
  let F6_layer_activation_b : [120]f64 = map2 ReLU_b F7_layer_b F6_layer
  let (F6_layer_b,F6_w_grad,F6_b_grad) = dense_b F6_layer_activation_b F5_layer F6_w
  let F5_layer_b = unflatten_3d 16 5 5 F6_layer_b
  let S4_layer_b = avg_pool_b F5_layer_b 2 :> [16][10][10]f64
  let C3_layer_activation_b = map2 (\ y_g y -> map2 (\ x_g x -> map2 ReLU_b x_g x) y_g y) S4_layer_b C3_layer
  let (C3_layer_b,C3_w_grad,C3_b_grad) = convolve2D_b C3_layer_activation_b S2_layer C3_w 0i64 4i64
  let S2_layer_b = avg_pool_b C3_layer_b 2 :> [6][28][28]f64
  let C1_layer_activation_b = map2 (\ y_g y -> map2 (\ x_g x -> map2 ReLU_b x_g x) y_g y) S2_layer_b C1_layer
  let (C1_layer_b,C1_w_grad,C1_b_grad) = convolve2D_b C1_layer_activation_b [img] C1_w 2i64 2i64
  in (C1_w_grad,C1_b_grad,C3_w_grad,C3_b_grad,F6_w_grad,F6_b_grad,F7_w_grad,F7_b_grad,F8_w_grad,F8_b_grad)
