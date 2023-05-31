import "../../gen_random/mk_random"

def main (seed : i32) (img_size : i64) (output_size : i64) =
  let img : [img_size]f64 = flatten (mk_rand_array seed 1 img_size) :> [img_size]f64

  let (dense_w,dense_b) = mk_dense_wandb seed output_size img_size
  in (img,dense_w,dense_b)