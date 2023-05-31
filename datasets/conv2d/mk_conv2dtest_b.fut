import "../../gen_random/mk_random"
import "../../layers/conv2d"

def main (seed : i32) (num_img : i64) (output_size : i64) (img_size : i64) (kernel_size : i64) =
  let seed_img = mk_rand_seeds seed num_img
  let img : [num_img][img_size][img_size]f64 = tabulate num_img (\ i -> mk_rand_array seed_img[i] img_size img_size)

  let (conv_w,conv_b) = mk_conv_wandb seed output_size num_img kernel_size kernel_size
  let grad = convolve2D img conv_w conv_b 1
  in (grad, img, conv_w) :> ([][][]f64,[][][]f64,[][][][]f64)