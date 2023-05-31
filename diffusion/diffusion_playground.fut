import "diffusion"
import "../gen_random/mk_random"
import "../utils/optimizers"

def main (x_train : [][][]f64)  =
let train_dataset = x_train[:1]
let epochs = 1
let seed = 44i32

let (losses,sampled_imgs,trained_weights) = ddpm_diffusion train_dataset epochs 1 seed
let (c_in_w,c_in_b) = trained_weights.0
let (b1_c1_w,b1_c1_b,b1_tw,b1_tb,b1_c2_w,b1_c2_b) = trained_weights.1
let (b2_c1_w,b2_c1_b,b2_tw,b2_tb,b2_c2_w,b2_c2_b) = trained_weights.2
let (b3_c1_w,b3_c1_b,b3_tw,b3_tb,b3_c2_w,b3_c2_b) = trained_weights.3
let (b4_c1_w,b4_c1_b,b4_tw,b4_tb,b4_c2_w,b4_c2_b) = trained_weights.4
let (c_out_w,c_out_b) = trained_weights.5
in (losses,sampled_imgs,c_in_w,c_in_b,b1_c1_w,b1_c1_b,b1_tw,b1_tb,b1_c2_w,b1_c2_b,b2_c1_w,b2_c1_b,b2_tw,b2_tb,b2_c2_w,b2_c2_b,b3_c1_w,b3_c1_b,b3_tw,b3_tb,b3_c2_w,b3_c2_b,b4_c1_w,b4_c1_b,b4_tw,b4_tb,b4_c2_w,b4_c2_b,c_out_w,c_out_b)
