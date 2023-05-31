import "../../gen_random/mk_random"
import "../../layers/groupnorm"

def main (seed : i32) (num_img : i64) (img_size : i64) =
  let seed_img = mk_rand_seeds seed num_img
  let img : [num_img][img_size][img_size]f64 = tabulate num_img (\ i -> mk_rand_array seed_img[i] img_size img_size)
  let (out,cache) = group_norm img 32 1e-05
  in (out, cache.0, cache.1, cache.2)