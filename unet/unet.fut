import "../layers/conv2d"
import "../layers/groupnorm"
import "../layers/dense"
import "../utils/actfun"
import "../utils/lossfun"

-- BLOCK WITH GROUPNORM
def block [l][n][m][t][o] (imgs: [l][n][m]f64) (time_mlp : [t]f64) (num_groups : i64) (weights) =
  let (conv1_w,conv1_b,t_w,t_b,conv2_w,conv2_b) = weights
  let conv1 : [o][n][m]f64 = convolve2D imgs conv1_w conv1_b 1 :> [o][n][m]f64
  let conv1_act : [o][n][m]f64 = ReLU_3d conv1
  let (conv1_gnorm,conv1_gnorm_cache) = group_norm conv1_act num_groups 1e-05
  let lin_out : [o]f64 = dense time_mlp t_w t_b
  let lin_out_act : [o]f64 = map ReLU lin_out
  let comb : [o][n][m]f64 = (map2 (\ conv lin -> map (\ c -> map (\c_ -> c_+lin) c) conv) conv1_gnorm lin_out_act)
  let conv2 : [o][n][m]f64 = convolve2D comb conv2_w conv2_b 1 :> [o][n][m]f64
  let conv2_act : [o][n][m]f64 = ReLU_3d conv2
  let (conv2_gnorm,conv2_gnorm_cache) = group_norm conv2_act num_groups 1e-05
  in (conv2_gnorm,(imgs,time_mlp,conv1,lin_out,comb,conv2,conv1_gnorm_cache,conv2_gnorm_cache))


def block_reverse [l][n][m] (out_grad: [l][n][m]f64) (num_groups : i64) (weights) (cache) =
  let (conv1_w,_,t_w,_,conv2_w,_) = weights
  let (imgs, time_mlp, conv1, lin_out, comb, conv2,conv1_gnorm_cache,conv2_gnorm_cache) = cache
  let conv2_gnorm_b = group_norm_b out_grad num_groups 1e-05 conv2_gnorm_cache
  let conv2_act_b = ReLU_3d_b conv2_gnorm_b conv2
  let (conv2_b,c2_w_grad,c2_b_grad) = convolve2D_b conv2_act_b comb conv2_w 1 1
  let conv1_gnorm_b = group_norm_b conv2_b num_groups 1e-05 conv1_gnorm_cache
  let out_grad_conv_act = ReLU_3d_b conv1_gnorm_b conv1
  let out_grad_sum = map (map (reduce (+) 0)) conv2_b
  let out_grad_lin_act = map2 ReLU_b (map (reduce (+) 0) out_grad_sum) lin_out
  let (_, t_w_grad, t_b_grad) = dense_b out_grad_lin_act time_mlp t_w
  let (input_grad, c_w_grad, c_b_grad) = convolve2D_b out_grad_conv_act imgs conv1_w 1 1
  in (input_grad, (c_w_grad, c_b_grad, t_w_grad, t_b_grad, c2_w_grad, c2_b_grad))


-- UNET
def unet_simple [n][m][t] (xt : [n][m]f64) (time_mlp : [t]f64) (num_groups : i64) (weights) =
  let (c_in,bd1_w,bd2_w,bu2_w,bu1_w,c_out) = weights
  let (c_inw,c_inb) = c_in
  let (c_outw,c_outb) = c_out
  let init_conv : [64][28][28]f64 = convolve2D [xt] c_inw c_inb 1 :> [64][28][28]f64
  let (block1_down,bd1_cache) = block init_conv time_mlp num_groups bd1_w
  let (block2_down,bd2_cache) = block block1_down time_mlp num_groups bd2_w
  let block2_down_cat = (concat_to 512 block2_down block2_down)
  let (block2_up,bu2_cache) = block block2_down_cat time_mlp num_groups bu2_w
  let block2_up = block2_up :> [128][28][28]f64
  let block2_up_cat = (concat_to 256 block2_up block1_down) :> [256][28][28]f64
  let (block1_up,bu1_cache) = block block2_up_cat time_mlp num_groups bu1_w
  let out_conv = convolve2D block1_up c_outw c_outb 0
  let out_conv = out_conv[0] :> [n][m]f64
  in (out_conv,(bd1_cache,bd2_cache,bu2_cache,bu1_cache,block1_up,num_groups))


def unet_simple_reverse [n][m] (xt : [n][m]f64) (prediction_2d : [n][m]f64) (noise : [n][m]f64) (weights) (cache) =
  let (bd1_cache,bd2_cache,bu2_cache,bu1_cache,out_conv_cache,num_groups) = cache
  let (c_in,bd1_w,bd2_w,bu2_w,bu1_w,c_out) = weights
  let (c_inw,_) = c_in
  let (c_outw,_) = c_out
  let grad_2d = mse_loss_img_prime noise prediction_2d
  let (out_conv_b,c_out_w_grad,c_out_b_grad) = convolve2D_b [grad_2d] out_conv_cache c_outw 0 0
  let (block1_up_b,bu1_grad) = block_reverse out_conv_b num_groups bu1_w bu1_cache
  let block1_up_b_ = block1_up_b :> [256][28][28]f64
  let block1_up_b : [128][28][28]f64 = block1_up_b_[:128] :> [128][28][28]f64
  let block1_up_b_cache : [128][28][28]f64 = block1_up_b_[128:256] :> [128][28][28]f64
  let (block2_up_b,bu2_grad) = block_reverse block1_up_b num_groups bu2_w bu2_cache
  let block2_up_b = block2_up_b :> [512][28][28]f64
  let block2_up_b : [256][28][28]f64 = map2 (map2 (map2 (+))) block2_up_b[:256] (block2_up_b[256:512] :> [256][28][28]f64)
  let (block2_down_b,bd2_grad) = block_reverse block2_up_b num_groups bd2_w bd2_cache
  let block2_down_b = block2_down_b :> [128][28][28]f64
  let block2_down_b = map2 (map2 (map2 (+))) block2_down_b block1_up_b_cache
  let (block1_down_b,bd1_grad) = block_reverse block2_down_b num_groups bd1_w bd1_cache
  let (_,c_in_w_grad,c_in_b_grad) = convolve2D_b block1_down_b [xt] c_inw 1 1
  let c_in_grad = (c_in_w_grad,c_in_b_grad)
  let c_out_grad = (c_out_w_grad, c_out_b_grad)
  in (c_in_grad,bd1_grad,bd2_grad,bu2_grad,bu1_grad,c_out_grad)

