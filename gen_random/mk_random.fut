import "lib/github.com/diku-dk/cpprandom/random"
module rng_engine = minstd_rand
module rand_f64 = normal_distribution f64 rng_engine
module rand_i64_uniform = uniform_int_distribution i64 rng_engine
module rand_f64_uniform = uniform_real_distribution f64 rng_engine

def mk_rand_seeds (seed : i32) (n : i64) : [n]i32 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (n) rng_state
  let rng_numb = (unzip (map (rand_i64_uniform.rand (0,999999)) rng_states)).1
  in map i32.i64 rng_numb

def mk_rand_int (seed : i32) (min_val : i64) (max_val : i64) : i64 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let (_,x) = rand_i64_uniform.rand (min_val,max_val) rng_state
  in x

def mk_rand_array (seed : i32) (n : i64) (m : i64) : [n][m]f64 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (n*m) rng_state
  let eps = map (\e -> (rand_f64.rand {mean=0, stddev=1} e).1) rng_states
  in unflatten n m eps

def mk_rand_array_uniform_real (seed : i32) (l : f64) (h : f64) (n : i64) (m : i64) : [n][m]f64 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (n*m) rng_state
  let rng_numb = map (\e -> (rand_f64_uniform.rand (l,h) e).1) rng_states
  in unflatten n m rng_numb

def mk_conv_weights  (seed : i32) (o : i64) (l : i64) (p : i64) (k : i64) : [o][l][p][k]f64 =
  let size = 1f64/( f64.i64 (l*(p*k)))
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (o*l*p*k) rng_state
  let rng_numb = map (\e -> (rand_f64_uniform.rand ((-f64.sqrt(size)),(f64.sqrt(size))) e).1) rng_states
  in unflatten_4d o l p k rng_numb

def mk_conv_biases (seed : i32) (o : i64) (l : i64) (p : i64) (k : i64) : [o]f64 =
  let size = 1f64/( f64.i64 (l*(p*k)))
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (o) rng_state
  let rng_numb = map (\e -> (rand_f64_uniform.rand ((-f64.sqrt(size)),(f64.sqrt(size))) e).1) rng_states
  in rng_numb

def mk_conv_wandb (seed : i32) (o : i64) (l : i64) (p : i64) (k : i64) : ([o][l][p][k]f64, [o]f64) =
  let seeds : [2]i32 = mk_rand_seeds seed 2
  let weights = mk_conv_weights seeds[0] o l p k
  let biases = mk_conv_biases seeds[1] o l p k
  in (weights, biases)

def mk_dense_weights (seed : i32) (m : i64) (n : i64) : [m][n]f64 =
  let size = 1f64/(f64.i64 n)
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (m*n) rng_state
  let rng_numb = map (\e -> (rand_f64_uniform.rand ((-f64.sqrt(size)),(f64.sqrt(size))) e).1) rng_states
  in unflatten m n rng_numb

def mk_dense_biases (seed : i32) (m : i64) (n : i64) : [m]f64 =
  let size = 1f64/(f64.i64 n)
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (m) rng_state
  let rng_numb = map (\e -> (rand_f64_uniform.rand ((-f64.sqrt(size)),(f64.sqrt(size))) e).1) rng_states
  in rng_numb

def mk_dense_wandb (seed : i32) (m : i64) (n : i64) : ([m][n]f64, [m]f64) =
  let seeds : [2]i32 = mk_rand_seeds seed 2
  let weights = mk_dense_weights seeds[0] m n
  let biases = mk_dense_biases seeds[1] m n
  in (weights, biases)


def mk_block_wandb (seed : i32) (c1_out : i64) (c1_in : i64) (k1_w : i64) (k1_h : i64) (t_o : i64) (t_i : i64) (c2_out : i64) (c2_in : i64) (k2_w : i64) (k2_h : i64) : ([c1_out][c1_in][k1_w][k1_h]f64,[c1_out]f64,[t_o][t_i]f64,[t_o]f64,[c2_out][c2_in][k2_w][k2_h]f64,[c2_out]f64) =
  let seeds = mk_rand_seeds seed 3
  let (conv1_w, conv1_b) = mk_conv_wandb seeds[0] c1_out c1_in k1_w k1_h
  let (time_w, time_b) = mk_dense_wandb seeds[1] t_o t_i
  let (conv2_w, conv2_b) = mk_conv_wandb seeds[2] c2_out c2_in k2_w k2_h
  in (conv1_w,conv1_b,time_w,time_b,conv2_w,conv2_b)

def mk_unet_wandb (seed : i32) =
  let seeds = mk_rand_seeds seed 6
  let c_in_wandb = mk_conv_wandb seeds[0] 64 1 3 3
  let bd1_wandb = mk_block_wandb seeds[1] 128 64 3 3 128 256 128 128 3 3
  let bd2_wandb = mk_block_wandb seeds[2] 256 128 3 3 256 256 256 256 3 3
  let bu2_wandb = mk_block_wandb seeds[3] 128 512 3 3 128 256 128 128 3 3
  let bu1_wandb = mk_block_wandb seeds[4] 64 256 3 3 64 256 64 64 3 3
  let c_out_wandb = mk_conv_wandb seeds[5] 1 64 1 1
  in (c_in_wandb, bd1_wandb, bd2_wandb, bu2_wandb, bu1_wandb, c_out_wandb)

def mk_lenet_wandb (seeds : [5]i32) =
  let (C1_w : [6][1][5][5]f64, C1_b : [6]f64)  = mk_conv_wandb seeds[0] 6 1 5 5
  let (C3_w : [16][6][5][5]f64, C3_b : [16]f64)  = mk_conv_wandb seeds[1] 16 6 5 5
  let (F6_w : [120][400]f64, F6_b : [120]f64) = mk_dense_wandb seeds[2] 120 400
  let (F7_w : [84][120]f64, F7_b : [84]f64) = mk_dense_wandb seeds[3] 84 120
  let (F8_w : [10][84]f64, F8_b : [10]f64) = mk_dense_wandb seeds[4] 10 84
  in (C1_w,C1_b,C3_w,C3_b,F6_w,F6_b,F7_w,F7_b,F8_w,F8_b)

 -- let (F7_w : [84][200]f64, F7_b : [84]f64) = mk_dense_wandb seeds[3] 84 200
 -- let (F8_w : [10][84]f64, F8_b : [10]f64) = mk_dense_wandb seeds[4] 10 84

def unzip_unet_wandb (weights : (([64][1][3][3]f64, [64]f64), ([128][64][3][3]f64, [128]f64, [128][256]f64, [128]f64, [128][128][3][3]f64, [128]f64), ([256][128][3][3]f64, [256]f64, [256][256]f64, [256]f64, [256][256][3][3]f64, [256]f64), ([128][512][3][3]f64, [128]f64, [128][256]f64, [128]f64, [128][128][3][3]f64, [128]f64), ([64][256][3][3]f64, [64]f64, [64][256]f64, [64]f64, [64][64][3][3]f64, [64]f64), ([1][64][1][1]f64, [1]f64))) =
  let (c_in_w,c_in_b) = weights.0
  let (b1_c1_w,b1_c1_b,b1_tw,b1_tb,b1_c2_w,b1_c2_b) = weights.1
  let (b2_c1_w,b2_c1_b,b2_tw,b2_tb,b2_c2_w,b2_c2_b) = weights.2
  let (b3_c1_w,b3_c1_b,b3_tw,b3_tb,b3_c2_w,b3_c2_b) = weights.3
  let (b4_c1_w,b4_c1_b,b4_tw,b4_tb,b4_c2_w,b4_c2_b) = weights.4
  let (c_out_w,c_out_b) = weights.5
  in (c_in_w,c_in_b,b1_c1_w,b1_c1_b,b1_tw,b1_tb,b1_c2_w,b1_c2_b,b2_c1_w,b2_c1_b,b2_tw,b2_tb,b2_c2_w,b2_c2_b,b3_c1_w,b3_c1_b,b3_tw,b3_tb,b3_c2_w,b3_c2_b,b4_c1_w,b4_c1_b,b4_tw,b4_tb,b4_c2_w,b4_c2_b,c_out_w,c_out_b)
